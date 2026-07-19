#!/usr/bin/env python3
"""下载并校验 APNIC 官方数据，导出 CN/HK/MO/TW IPv4/IPv6 CIDR 清单。"""

from __future__ import annotations

import argparse
import ipaddress
import shutil
import sys
import tempfile
import urllib.error
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence

from 公共工具 import (
    Network,
    collapse_networks,
    download,
    file_hashes,
    interval_difference,
    load_json,
    md5_file,
    network_stats,
    parse_apnic,
    promote,
    read_network_file,
    sha256_file,
    utc_now,
    verify_official_md5,
    write_json,
)


@dataclass(frozen=True)
class ApnicHeader:
    serial: str
    expected_records: int
    start_date: str
    end_date: str
    utc_offset: str
    actual_records: int
    type_counts: dict[str, int]


def validate_date(value: str, field_name: str) -> None:
    try:
        datetime.strptime(value, "%Y%m%d")
    except ValueError as exc:
        raise ValueError(f"APNIC {field_name}格式无效：{value}") from exc


def validate_apnic_file(path: Path, max_source_age_days: int) -> ApnicHeader:
    """校验版本头、总记录数、分类汇总、日期和记录基本结构。"""
    version_header: Optional[List[str]] = None
    summary_counts: dict[str, int] = {}
    actual_counts = {"asn": 0, "ipv4": 0, "ipv6": 0}
    actual_records = 0

    with path.open("r", encoding="utf-8", errors="strict") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split("|")
            if fields[0] == "2":
                if version_header is not None:
                    raise ValueError("APNIC 文件包含多个版本头")
                if len(fields) != 7 or fields[1].lower() != "apnic":
                    raise ValueError(f"第 {line_number} 行版本头无效")
                version_header = fields
                continue
            if len(fields) == 6 and fields[0].lower() == "apnic" and fields[1] == "*":
                resource_type = fields[2].lower()
                if resource_type not in actual_counts or fields[5].lower() != "summary":
                    raise ValueError(f"第 {line_number} 行汇总记录无效")
                summary_counts[resource_type] = int(fields[4])
                continue
            if len(fields) < 7 or fields[0].lower() != "apnic":
                raise ValueError(f"第 {line_number} 行 APNIC 记录结构无效")
            resource_type = fields[2].lower()
            if resource_type not in actual_counts:
                raise ValueError(f"第 {line_number} 行资源类型无效：{resource_type}")
            actual_counts[resource_type] += 1
            actual_records += 1

    if version_header is None:
        raise ValueError("APNIC 文件缺少版本头")
    if set(summary_counts) != set(actual_counts):
        raise ValueError("APNIC 文件缺少 ASN、IPv4 或 IPv6 汇总记录")

    expected_records = int(version_header[3])
    if actual_records != expected_records:
        raise ValueError(
            f"APNIC 总记录数校验失败：版本头 {expected_records}，实际 {actual_records}"
        )
    for resource_type, expected_count in summary_counts.items():
        if actual_counts[resource_type] != expected_count:
            raise ValueError(
                f"APNIC {resource_type} 记录数校验失败：汇总 {expected_count}，"
                f"实际 {actual_counts[resource_type]}"
            )

    start_date, end_date = version_header[4], version_header[5]
    validate_date(start_date, "开始日期")
    validate_date(end_date, "报告日期")
    source_date = datetime.strptime(end_date, "%Y%m%d").date()
    age_days = (utc_now().date() - source_date).days
    if age_days < 0 or age_days > max_source_age_days:
        raise ValueError(
            f"APNIC 报告日期异常：{end_date}，距当前 UTC 日期 {age_days} 天，"
            f"允许范围为 0～{max_source_age_days} 天"
        )
    return ApnicHeader(
        serial=version_header[2],
        expected_records=expected_records,
        start_date=start_date,
        end_date=end_date,
        utc_offset=version_header[6],
        actual_records=actual_records,
        type_counts=actual_counts,
    )


def write_networks(path: Path, networks: Sequence[Network]) -> None:
    values = [str(network) for network in networks]
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(values) + ("\n" if values else ""))


def select_version(networks: Sequence[Network], version: int) -> list[Network]:
    return [network for network in networks if network.version == version]


def address_difference(left: Sequence[Network], right: Sequence[Network]) -> list[Network]:
    """按实际地址空间求差，避免聚合边界变化产生虚假的删除记录。"""
    return collapse_networks(
        [
            *interval_difference(left, right, 4),
            *interval_difference(left, right, 6),
        ]
    )


def empty_stats() -> dict:
    return {
        "IPv4": {"CIDR数量": 0, "地址数量": "0"},
        "IPv6": {"CIDR数量": 0, "地址数量": "0"},
    }


def removal_ratio(removed: Sequence[Network], old: Sequence[Network], version: int) -> float:
    removed_count = sum(item.num_addresses for item in removed if item.version == version)
    old_count = sum(item.num_addresses for item in old if item.version == version)
    return removed_count / old_count if old_count else 0.0


def region_file_name(region: str, display_name: str, version: int) -> str:
    return f"{region}_{display_name}_IPv{version}.txt"


def load_previous(current_dir: Path, regions: dict[str, str]) -> dict[str, dict[int, list[Network]]]:
    previous: dict[str, dict[int, list[Network]]] = {}
    for region in regions:
        previous[region] = {}
        for version in (4, 6):
            previous[region][version] = read_network_file(
                current_dir / region_file_name(region, regions[region], version)
            )
    return previous


def build_diff(
    candidate: Path,
    regions: dict[str, str],
    new_data: dict[str, dict[int, list[Network]]],
    old_data: dict[str, dict[int, list[Network]]],
) -> tuple[dict, list[Network], list[Network]]:
    diff_dir = candidate / "差异"
    diff_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, dict] = {}

    for region, display_name in regions.items():
        summary[region] = {"名称": display_name}
        for version in (4, 6):
            new_networks = new_data[region][version]
            old_networks = old_data[region][version]
            added = address_difference(new_networks, old_networks)
            removed = address_difference(old_networks, new_networks)
            prefix = f"{region}_{display_name}_IPv{version}"
            write_networks(diff_dir / f"{prefix}_新增.txt", added)
            write_networks(diff_dir / f"{prefix}_删除.txt", removed)
            summary[region][f"IPv{version}"] = {
                "上一版本CIDR数": len(old_networks),
                "当前CIDR数": len(new_networks),
                "新增CIDR数": len(added),
                "删除CIDR数": len(removed),
                "新增地址数": str(sum(item.num_addresses for item in added)),
                "删除地址数": str(sum(item.num_addresses for item in removed)),
            }

    new_all = collapse_networks(
        [
            network
            for region in regions
            for version in (4, 6)
            for network in new_data[region][version]
        ]
    )
    old_all = collapse_networks(
        [
            network
            for region in regions
            for version in (4, 6)
            for network in old_data[region][version]
        ]
    )
    all_added = address_difference(new_all, old_all)
    all_removed = address_difference(old_all, new_all)
    for version in (4, 6):
        write_networks(
            diff_dir / f"CN_HK_MO_TW_全部_IPv{version}_新增.txt", select_version(all_added, version)
        )
        write_networks(
            diff_dir / f"CN_HK_MO_TW_全部_IPv{version}_删除.txt", select_version(all_removed, version)
        )
    write_networks(diff_dir / "CN_HK_MO_TW_全部_新增.txt", all_added)
    write_networks(diff_dir / "CN_HK_MO_TW_全部_删除.txt", all_removed)
    summary["全部"] = {
        "上一版本": network_stats(old_all) if old_all else empty_stats(),
        "当前版本": network_stats(new_all),
        "新增": network_stats(all_added),
        "删除": network_stats(all_removed),
        "新增CIDR数": len(all_added),
        "删除CIDR数": len(all_removed),
    }
    return summary, all_added, all_removed


def write_summary_text(
    path: Path,
    header: ApnicHeader,
    regions: dict[str, str],
    new_data: dict[str, dict[int, list[Network]]],
    diff_summary: dict,
    official_md5: str,
) -> None:
    lines = [
        "APNIC 四地区地址清单执行结果",
        "=" * 36,
        "执行状态：成功",
        f"APNIC 报告日期：{header.end_date}",
        f"APNIC 序列号：{header.serial}",
        f"官方 MD5：{official_md5}",
        f"源文件记录数：{header.actual_records}",
        "",
    ]
    for region, display_name in regions.items():
        v4 = new_data[region][4]
        v6 = new_data[region][6]
        region_diff = diff_summary[region]
        lines.extend(
            [
                f"{region}（{display_name}）：",
                f"  IPv4：{len(v4)} 个 CIDR；新增 {region_diff['IPv4']['新增CIDR数']}；"
                f"删除 {region_diff['IPv4']['删除CIDR数']}",
                f"  IPv6：{len(v6)} 个 CIDR；新增 {region_diff['IPv6']['新增CIDR数']}；"
                f"删除 {region_diff['IPv6']['删除CIDR数']}",
            ]
        )
    all_diff = diff_summary["全部"]
    lines.extend(
        [
            "",
            f"总合集 IPv4：{all_diff['当前版本']['IPv4']['CIDR数量']} 个 CIDR",
            f"总合集 IPv6：{all_diff['当前版本']['IPv6']['CIDR数量']} 个 CIDR",
            f"相对上一版本新增：{all_diff['新增CIDR数']} 个 CIDR",
            f"相对上一版本删除：{all_diff['删除CIDR数']} 个 CIDR",
        ]
    )
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")


def relative_text(path: Path, project_root: Path) -> str:
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError:
        return path.name


def print_result(summary_path: Path, output_dir: Path, project_root: Path) -> None:
    print(summary_path.read_text(encoding="utf-8"), end="")
    print(f"输出目录：{relative_text(output_dir, project_root)}")
    print("=" * 36)


def verify_export_directory(directory: Path, regions: Sequence[str]) -> None:
    """对已生成目录执行文件哈希、CIDR 和统计一致性复核。"""
    manifest_path = directory / "校验清单.json"
    if not manifest_path.is_file():
        raise ValueError(f"导出目录缺少校验清单：{directory.name}")
    manifest = load_json(manifest_path)
    errors: list[str] = []
    for relative_path, expected_hash in manifest.get("文件SHA256", {}).items():
        path = directory / Path(relative_path)
        if not path.is_file():
            errors.append(f"文件缺失：{relative_path}")
        elif sha256_file(path) != expected_hash:
            errors.append(f"文件哈希不匹配：{relative_path}")

    combined: list[Network] = []
    for region in regions:
        region_networks: list[Network] = []
        for version in (4, 6):
            display_name = manifest["地区统计"][region]["名称"]
            path = directory / region_file_name(region, display_name, version)
            networks = read_network_file(path)
            if any(network.version != version for network in networks):
                errors.append(f"{path.name} 包含错误 IP 版本")
            region_networks.extend(networks)
            combined.extend(networks)
        expected_stats = manifest["地区统计"][region]["统计"]
        if network_stats(region_networks) != expected_stats:
            errors.append(f"{region} 统计与 manifest 不一致")

    combined = collapse_networks(combined)
    exported_all = read_network_file(directory / "CN_HK_MO_TW_全部_IPv4和IPv6.txt")
    exported_v4 = read_network_file(directory / "CN_HK_MO_TW_全部_IPv4.txt")
    exported_v6 = read_network_file(directory / "CN_HK_MO_TW_全部_IPv6.txt")
    if combined != exported_all:
        errors.append("双栈总文件与四地区合并结果不一致")
    if select_version(exported_all, 4) != exported_v4:
        errors.append("IPv4 总文件与双栈总文件的 IPv4 部分不一致")
    if select_version(exported_all, 6) != exported_v6:
        errors.append("IPv6 总文件与双栈总文件的 IPv6 部分不一致")
    if network_stats(exported_all) != manifest["总合集统计"]:
        errors.append("总合集统计与 manifest 不一致")
    if errors:
        raise ValueError("；".join(errors))


def run_export(args: argparse.Namespace) -> int:
    config_path = Path(args.config).resolve()
    project_root = config_path.parent.parent
    config = load_json(config_path)
    regions: dict[str, str] = {
        key.upper(): value for key, value in config["地区"].items()
    }
    output_root_value = Path(config["输出目录"])
    output_root = (
        output_root_value
        if output_root_value.is_absolute()
        else project_root / output_root_value
    )
    candidates_root = output_root / "候选版本"
    history_root = output_root / "历史版本"
    current_dir = output_root / "当前版本"
    candidates_root.mkdir(parents=True, exist_ok=True)
    timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    candidate = candidates_root / timestamp
    candidate.mkdir(parents=True)

    with tempfile.TemporaryDirectory(prefix="apnic-region-") as temporary:
        temporary_dir = Path(temporary)
        source_path = temporary_dir / "delegated-apnic-latest"
        checksum_path = temporary_dir / "delegated-apnic-latest.md5"
        if args.offline_source:
            shutil.copy2(Path(args.offline_source).resolve(), source_path)
            official_md5 = md5_file(source_path)
            source_mode = "离线测试数据（未进行在线官方 MD5 校验）"
        else:
            timeout = int(config["APNIC数据源"]["超时秒数"])
            download(config["APNIC数据源"]["数据地址"], source_path, timeout)
            download(config["APNIC数据源"]["MD5地址"], checksum_path, timeout)
            official_md5 = verify_official_md5(source_path, checksum_path)
            source_mode = "APNIC HTTPS 下载并通过官方 MD5 校验"

        header = validate_apnic_file(
            source_path, int(config["校验"]["数据最大滞后天数"])
        )
        statuses = {item.lower() for item in config["记录状态"]}
        new_data: dict[str, dict[int, list[Network]]] = {}
        source_records: dict[str, int] = {}
        failures: list[str] = []
        for region in regions:
            networks, source_info = parse_apnic(source_path, {region}, statuses)
            if source_info.report_end_date != header.end_date:
                failures.append(f"{region} 解析报告日期与文件头不一致")
            new_data[region] = {
                4: select_version(networks, 4),
                6: select_version(networks, 6),
            }
            source_records[region] = source_info.matched_records
            minimums = config["校验"]["最少CIDR数量"][region]
            for version in (4, 6):
                actual = len(new_data[region][version])
                minimum = int(minimums[f"IPv{version}"])
                if actual < minimum:
                    failures.append(
                        f"{region} IPv{version} CIDR 数量 {actual} 低于下限 {minimum}"
                    )

        old_data = load_previous(current_dir, regions)
        diff_summary, all_added, all_removed = build_diff(
            candidate, regions, new_data, old_data
        )
        max_removal_ratio = float(config["校验"]["最大删除地址比例"])
        if current_dir.exists():
            for region in regions:
                for version in (4, 6):
                    removed = address_difference(
                        old_data[region][version], new_data[region][version]
                    )
                    removed_ratio = removal_ratio(
                        removed, old_data[region][version], version
                    )
                    if removed_ratio > max_removal_ratio:
                        failures.append(
                            f"{region} IPv{version} 删除地址比例 {removed_ratio:.6%} "
                            f"超过门限 {max_removal_ratio:.6%}"
                        )

        if args.force_large_change:
            failures = [
                failure for failure in failures if "删除地址比例" not in failure
            ]

        all_networks: list[Network] = []
        for region in regions:
            for version in (4, 6):
                networks = new_data[region][version]
                write_networks(
                    candidate / region_file_name(region, regions[region], version), networks
                )
                all_networks.extend(networks)
        all_networks = collapse_networks(all_networks)
        write_networks(
            candidate / "CN_HK_MO_TW_全部_IPv4.txt", select_version(all_networks, 4)
        )
        write_networks(
            candidate / "CN_HK_MO_TW_全部_IPv6.txt", select_version(all_networks, 6)
        )
        write_networks(candidate / "CN_HK_MO_TW_全部_IPv4和IPv6.txt", all_networks)
        write_json(candidate / "差异" / "变更摘要.json", diff_summary)
        write_summary_text(
            candidate / "执行结果.txt",
            header,
            regions,
            new_data,
            diff_summary,
            official_md5,
        )

        promoted = not failures and not args.dry_run
        manifest = {
            "格式版本": 1,
            "生成时间_UTC": utc_now().isoformat(),
            "是否已启用": promoted,
            "数据源": {
                "数据地址": config["APNIC数据源"]["数据地址"],
                "MD5地址": config["APNIC数据源"]["MD5地址"],
                "获取方式": source_mode,
                "官方MD5": official_md5,
                "源文件SHA256": sha256_file(source_path),
                "序列号": header.serial,
                "报告开始日期": header.start_date,
                "报告结束日期": header.end_date,
                "文件头记录数": header.expected_records,
                "实际记录数": header.actual_records,
                "分类记录数": header.type_counts,
            },
            "地区统计": {
                region: {
                    "名称": display_name,
                    "匹配源记录数": source_records[region],
                    "统计": network_stats(
                        [*new_data[region][4], *new_data[region][6]]
                    ),
                }
                for region, display_name in regions.items()
            },
            "总合集统计": network_stats(all_networks),
            "差异": {
                "新增CIDR数": len(all_added),
                "删除CIDR数": len(all_removed),
            },
            "校验失败": failures,
        }
        manifest["文件SHA256"] = file_hashes(candidate)
        write_json(candidate / "校验清单.json", manifest)
        verify_export_directory(candidate, list(regions))

    if failures:
        print("执行结果：失败，候选文件未提升为当前版本", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        print(f"候选目录：{relative_text(candidate, project_root)}", file=sys.stderr)
        return 2
    if args.dry_run:
        print("执行结果：演练成功，未替换当前版本")
        print_result(candidate / "执行结果.txt", candidate, project_root)
        return 0

    promote(candidate, current_dir, history_root, timestamp)
    verify_export_directory(current_dir, list(regions))
    if candidate.exists():
        shutil.rmtree(candidate)
    history_versions = sorted(
        [path for path in history_root.iterdir() if path.is_dir()],
        key=lambda path: path.name,
        reverse=True,
    )
    for expired in history_versions[3:]:
        shutil.rmtree(expired)
    print_result(current_dir / "执行结果.txt", current_dir, project_root)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="获取 APNIC 最新数据并导出 CN/HK/MO/TW IPv4/IPv6 CIDR 清单"
    )
    parser.add_argument("--config", required=True, help="配置文件路径")
    parser.add_argument(
        "--演练", "--dry-run", dest="dry_run", action="store_true", help="只生成候选版本"
    )
    parser.add_argument(
        "--离线数据",
        "--offline-source",
        dest="offline_source",
        help="使用本地 APNIC 文件，仅用于测试",
    )
    parser.add_argument(
        "--强制大变更",
        "--force-large-change",
        dest="force_large_change",
        action="store_true",
        help="人工审核后忽略删除比例门禁，不会绕过 MD5、文件头和日期校验",
    )
    return parser


def main() -> int:
    try:
        return run_export(build_parser().parse_args())
    except (OSError, ValueError, KeyError, RuntimeError, urllib.error.URLError) as exc:
        print(f"执行结果：失败", file=sys.stderr)
        print(f"失败原因：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
