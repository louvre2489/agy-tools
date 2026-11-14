#!/usr/bin/env python3
"""単一責任: CLI引数の解釈と各モジュール（収集・検出・レポート出力）のオーケストレーションを行うエントリポイント。"""

import argparse
from itertools import chain
from pathlib import Path
import sys

from detectors import build_detection_rules, scan_lines
from git_collector import (
    NotAGitRepositoryError,
    collect_git_history_lines,
    collect_working_tree_lines,
    verify_git_repository,
)
from models import ScanSummary
from reporter import format_terminal_report


def parse_args(argv: list[str]) -> argparse.Namespace:
    """コマンドライン引数を解析する。"""
    parser = argparse.ArgumentParser(
        description="Git管理下のリポジトリ（Working Treeおよび全コミット履歴）から機微情報を検査します。"
    )
    parser.add_argument(
        "repo_path",
        nargs="?",
        default=".",
        help="検査対象のリポジトリパス（デフォルト: カレントディレクトリ '.'）",
    )
    return parser.parse_args(argv)


def run_scan(target_path_str: str) -> int:
    """スキャンを実行し、レポートを標準出力へ表示して終了コードを返す。"""
    target_path = Path(target_path_str).resolve()
    try:
        repo_root = verify_git_repository(target_path)
    except NotAGitRepositoryError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    rules = build_detection_rules()
    scanned_files, working_tree_lines = collect_working_tree_lines(repo_root)
    scanned_commits, history_lines_iter = collect_git_history_lines(repo_root)

    all_findings = scan_lines(chain(working_tree_lines, history_lines_iter), rules)
    summary = ScanSummary(
        target_repo=str(repo_root),
        scanned_files_count=scanned_files,
        scanned_commits_count=scanned_commits,
        findings=tuple(all_findings),
    )

    report = format_terminal_report(summary)
    print(report)

    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(run_scan(parse_args(sys.argv[1:]).repo_path))
