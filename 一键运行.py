#!/usr/bin/env python3
"""中国 IP 白名单工具的一键运行入口。"""

import runpy
import sys
from datetime import datetime
from pathlib import Path


class 同步输出:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, text):
        for stream in self.streams:
            stream.write(text)
            stream.flush()
        return len(text)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    项目目录 = Path(__file__).resolve().parent
    程序目录 = 项目目录 / "程序"
    配置文件 = 项目目录 / "配置" / "配置.json"
    主程序 = 程序目录 / "APNIC地址导出.py"
    日志目录 = 项目目录 / "日志"
    日志目录.mkdir(parents=True, exist_ok=True)
    日志文件 = 日志目录 / ("运行记录-" + datetime.now().strftime("%Y%m%d-%H%M%S") + ".log")

    原标准输出 = sys.stdout
    原错误输出 = sys.stderr
    退出码 = 0
    with 日志文件.open("w", encoding="utf-8") as 日志:
        sys.stdout = 同步输出(原标准输出, 日志)
        sys.stderr = 同步输出(原错误输出, 日志)
        try:
            sys.path.insert(0, str(程序目录))
            用户参数 = sys.argv[1:]
            sys.argv = ["一键运行.py", "--config", str(配置文件), *用户参数]
            runpy.run_path(str(主程序), run_name="__main__")
        except SystemExit as exc:
            退出码 = int(exc.code or 0)
        except Exception as exc:
            退出码 = 1
            print("一键运行结果：失败")
            print("失败原因：" + str(exc))
        finally:
            if 退出码 == 0:
                print("一键运行结果：成功")
            else:
                print("一键运行结果：失败，退出码：" + str(退出码))
            print("日志文件：" + 日志文件.relative_to(项目目录).as_posix())
            sys.stdout = 原标准输出
            sys.stderr = 原错误输出
    历史日志 = sorted(日志目录.glob("运行记录-*.log"), reverse=True)
    for 过期日志 in 历史日志[10:]:
        过期日志.unlink()
    return 退出码


if __name__ == "__main__":
    raise SystemExit(main())
