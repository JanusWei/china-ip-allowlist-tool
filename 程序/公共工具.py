#!/usr/bin/env python3
"""APNIC 地址导出程序使用的公共函数，仅使用 Python 标准库。"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shutil
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence, Union


Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass(frozen=True)
class SourceInfo:
    report_end_date: str
    latest_record_date: str
    matched_records: int


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def write_json(path: Path, value: object) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def md5_file(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, destination: Path, timeout: int) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "china-ip-allowlist-tool/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if getattr(response, "status", 200) != 200:
            raise RuntimeError(f"下载失败，HTTP 状态码：{response.status}")
        with destination.open("wb") as handle:
            shutil.copyfileobj(response, handle)


def verify_official_md5(source_path: Path, checksum_path: Path) -> str:
    checksum_text = checksum_path.read_text(encoding="ascii", errors="replace")
    match = re.search(r"\b([0-9a-fA-F]{32})\b", checksum_text)
    if not match:
        raise ValueError("APNIC 官方 MD5 文件中没有有效校验值")
    expected = match.group(1).lower()
    actual = md5_file(source_path).lower()
    if actual != expected:
        raise ValueError(f"官方 MD5 校验失败：期望 {expected}，实际 {actual}")
    return actual


def collapse_networks(networks: Iterable[Network]) -> list[Network]:
    network_list = list(networks)
    ipv4 = [network for network in network_list if network.version == 4]
    ipv6 = [network for network in network_list if network.version == 6]
    return sorted(
        [*ipaddress.collapse_addresses(ipv4), *ipaddress.collapse_addresses(ipv6)],
        key=lambda network: (
            network.version,
            int(network.network_address),
            network.prefixlen,
        ),
    )


def parse_apnic(
    source_path: Path,
    country_codes: set[str],
    allowed_statuses: set[str],
) -> tuple[list[Network], SourceInfo]:
    networks: list[Network] = []
    dates: list[str] = []
    report_end_date = "未知"
    matched_records = 0
    with source_path.open("r", encoding="utf-8", errors="strict") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split("|")
            if len(fields) >= 6 and fields[0] == "2" and fields[1].lower() == "apnic":
                report_end_date = fields[5]
                continue
            if len(fields) < 7 or fields[0].lower() != "apnic":
                continue
            _, country, resource_type, start, value, date, status = fields[:7]
            if country.upper() not in country_codes:
                continue
            if status.lower() not in allowed_statuses:
                continue
            if resource_type not in {"ipv4", "ipv6"}:
                continue
            try:
                if resource_type == "ipv4":
                    count = int(value)
                    if count <= 0:
                        raise ValueError("IPv4 地址数量必须大于零")
                    first = ipaddress.IPv4Address(start)
                    last = ipaddress.IPv4Address(int(first) + count - 1)
                    parsed = list(ipaddress.summarize_address_range(first, last))
                else:
                    parsed = [ipaddress.IPv6Network(f"{start}/{int(value)}", strict=True)]
            except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
                raise ValueError(f"第 {line_number} 行 APNIC 记录无效：{line}") from exc
            for network in parsed:
                if not network.is_global:
                    raise ValueError(f"第 {line_number} 行产生非公网网段：{network}")
                networks.append(network)
            matched_records += 1
            if date.isdigit() and len(date) == 8:
                dates.append(date)
    if not networks:
        raise ValueError("没有解析到符合地区和状态条件的公网地址")
    return collapse_networks(networks), SourceInfo(
        report_end_date=report_end_date,
        latest_record_date=max(dates) if dates else "未知",
        matched_records=matched_records,
    )


def read_network_file(path: Path) -> list[Network]:
    if not path.exists():
        return []
    result: list[Network] = []
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8-sig").splitlines(), start=1
    ):
        value = raw_line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ValueError(f"{path.name} 第 {line_number} 行不是规范 CIDR：{value}") from exc
        if not network.is_global:
            raise ValueError(f"{path.name} 第 {line_number} 行不是公网 CIDR：{value}")
        result.append(network)
    return collapse_networks(result)


def interval_difference(
    left: Sequence[Network], right: Sequence[Network], version: int
) -> list[Network]:
    left_intervals = sorted(
        (int(net.network_address), int(net.broadcast_address))
        for net in left
        if net.version == version
    )
    right_intervals = sorted(
        (int(net.network_address), int(net.broadcast_address))
        for net in right
        if net.version == version
    )
    result: list[Network] = []
    right_index = 0
    address_type = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    for start, end in left_intervals:
        cursor = start
        while right_index < len(right_intervals) and right_intervals[right_index][1] < cursor:
            right_index += 1
        scan_index = right_index
        while scan_index < len(right_intervals) and right_intervals[scan_index][0] <= end:
            other_start, other_end = right_intervals[scan_index]
            if other_start > cursor:
                result.extend(
                    ipaddress.summarize_address_range(
                        address_type(cursor), address_type(other_start - 1)
                    )
                )
            cursor = max(cursor, other_end + 1)
            if cursor > end:
                break
            scan_index += 1
        if cursor <= end:
            result.extend(
                ipaddress.summarize_address_range(address_type(cursor), address_type(end))
            )
    return collapse_networks(result)


def network_stats(networks: Sequence[Network]) -> dict:
    result = {}
    for version in (4, 6):
        selected = [network for network in networks if network.version == version]
        result[f"IPv{version}"] = {
            "CIDR数量": len(selected),
            "地址数量": str(sum(network.num_addresses for network in selected)),
        }
    return result


def file_hashes(directory: Path) -> dict[str, str]:
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.name != "校验清单.json":
            result[path.relative_to(directory).as_posix()] = sha256_file(path)
    return result


def promote(candidate: Path, current: Path, history_root: Path, timestamp: str) -> None:
    history_root.mkdir(parents=True, exist_ok=True)
    backup = current.parent / f".当前版本备份-{timestamp}"
    if backup.exists():
        shutil.rmtree(backup)
    if current.exists():
        shutil.copytree(current, history_root / timestamp)
        current.rename(backup)
    try:
        shutil.copytree(candidate, current)
    except Exception:
        if current.exists():
            shutil.rmtree(current)
        if backup.exists():
            backup.rename(current)
        raise
    finally:
        if backup.exists():
            shutil.rmtree(backup)
