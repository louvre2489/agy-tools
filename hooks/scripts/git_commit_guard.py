#!/usr/bin/env python3
"""単一責任: PreToolUse Hook の入出力を制御し、git commit 時に sensitive-info-checker を実行して判定結果を返すモジュール。"""

import json
from pathlib import Path
import subprocess
import sys

from command_parser import extract_git_commit_targets


def _resolve_scanner_script() -> Path:
    """sensitive-info-checker の scan.py スクリプトパスを解決する。"""
    global_skill_scanner = (
        Path.home()
        / ".gemini"
        / "config"
        / "skills"
        / "sensitive-info-checker"
        / "scripts"
        / "scan.py"
    )
    if global_skill_scanner.is_file():
        return global_skill_scanner

    # シンボリックリンク解決前のリポジトリ相対パスへのフォールバック
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "skills" / "sensitive-info-checker" / "scripts" / "scan.py"


def _emit_decision(decision: str, reason: str = "") -> None:
    """PreToolUse コントラクトに準拠した JSON を標準出力へ書き出す。"""
    payload: dict[str, str] = {"decision": decision}
    if reason:
        payload["reason"] = reason
    print(json.dumps(payload, ensure_ascii=False))


def main() -> int:
    """PreToolUse Hook のメイン処理。"""
    try:
        raw_input = sys.stdin.read()
        data = json.loads(raw_input) if raw_input.strip() else {}
    except json.JSONDecodeError:
        _emit_decision("allow")
        return 0

    tool_call = data.get("toolCall") or {}
    if tool_call.get("name") != "run_command":
        _emit_decision("allow")
        return 0

    args = tool_call.get("args") or {}
    command_line = args.get("CommandLine") or ""

    default_cwd = data.get("cwd") or ""
    if not default_cwd:
        workspace_paths = data.get("workspacePaths") or []
        if workspace_paths:
            default_cwd = workspace_paths[0]

    targets = extract_git_commit_targets(command_line, default_cwd)
    if not targets:
        _emit_decision("allow")
        return 0

    scanner_script = _resolve_scanner_script()
    if not scanner_script.is_file():
        _emit_decision(
            "force_ask",
            f"⚠️ [sensitive-info-checker] スキャナスクリプトが見つかりません: {scanner_script}\n"
            "このまま git commit を続行してよいか確認してください。",
        )
        return 0

    flagged_reports: list[str] = []

    for target_dir in targets:
        proc = subprocess.run(
            [sys.executable, str(scanner_script), str(target_dir)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 1:
            flagged_reports.append(proc.stdout.strip())
        elif proc.returncode != 0:
            err_msg = proc.stderr.strip() or proc.stdout.strip()
            flagged_reports.append(f"[検査エラー ({target_dir})]\n{err_msg}")

    if not flagged_reports:
        _emit_decision("allow")
        return 0

    combined_report = "\n\n---\n\n".join(flagged_reports)
    reason_message = (
        "⚠️ [sensitive-info-checker] git commit 実行前の機微情報スキャンで確認が必要な項目が検出されました。\n"
        "以下のマスク済みレポートを確認し、誤検知（False Positive）である場合のみ実行を承認してください。\n\n"
        f"{combined_report}"
    )
    _emit_decision("force_ask", reason_message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
