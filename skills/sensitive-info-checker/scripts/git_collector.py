"""単一責任: Git管理状態の検証、ワーキングツリーおよび過去の全コミット履歴からの検査対象行の収集を行うモジュール。"""

from pathlib import Path
import subprocess
from typing import Iterator

from models import SourceLine

# スキャン対象外とするファイルサイズ上限 (1MB)
_MAX_FILE_BYTES = 1_048_576

# 自身の検査ルール定義ファイルは正規表現パターンの誤検知を防ぐため除外する
_SELF_EXCLUDED_SUFFIXES = (
    "skills/sensitive-info-checker/scripts/detectors.py",
    "skills/sensitive-info-checker/scripts/validators.py",
)

# 検査対象外とするファイル名（完全一致）
_EXCLUDED_FILENAMES = (
    ".gitconfig",
)


class NotAGitRepositoryError(RuntimeError):
    """対象ディレクトリがGit管理下のリポジトリではない場合に送出される例外。"""


def verify_git_repository(repo_path: Path) -> Path:
    """指定されたパスがGit管理下のリポジトリか検証し、リポジトリルートパスを返す。"""
    if not repo_path.exists() or not repo_path.is_dir():
        raise NotAGitRepositoryError(f"指定されたパスが存在しないかディレクトリではありません: {repo_path}")

    result = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise NotAGitRepositoryError(
            f"指定されたパスはGit管理下のリポジトリではありません: {repo_path}\n"
            "このスキルはGitHubへの誤アップロード防止を目的としているため、Git管理されたリポジトリ内でのみ実行できます。"
        )
    return Path(result.stdout.strip()).resolve()


def _is_excluded_path(rel_path: str) -> bool:
    """検査対象外ファイル（.gitconfig やスキャン自身のパターン定義ファイル等）を除外判定する。"""
    normalized = rel_path.replace("\\", "/")
    filename = normalized.rsplit("/", 1)[-1]
    if filename in _EXCLUDED_FILENAMES:
        return True
    return any(normalized.endswith(suffix) for suffix in _SELF_EXCLUDED_SUFFIXES)


def collect_working_tree_lines(repo_root: Path) -> tuple[int, list[SourceLine]]:
    """ワーキングツリー内の追跡ファイル・未追跡ファイル（.gitignore除外を除く）から行を収集する。"""
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        capture_output=True,
        check=True,
    )
    raw_paths = [p.decode("utf-8", errors="replace") for p in result.stdout.split(b"\0") if p]

    lines: list[SourceLine] = []
    scanned_files = 0

    for rel_path in raw_paths:
        if _is_excluded_path(rel_path):
            continue
        full_path = repo_root / rel_path
        if not full_path.is_file() or full_path.is_symlink():
            continue
        try:
            if full_path.stat().st_size > _MAX_FILE_BYTES:
                continue
            raw_bytes = full_path.read_bytes()
        except OSError:
            continue

        # バイナリファイル判定（NULバイトが含まれる場合はスキップ）
        if b"\x00" in raw_bytes[:8192]:
            continue

        scanned_files += 1
        text = raw_bytes.decode("utf-8", errors="replace")
        for idx, line_content in enumerate(text.splitlines(), start=1):
            lines.append(
                SourceLine(
                    source_type="WORKING_TREE",
                    commit_hash=None,
                    file_path=rel_path,
                    line_number=idx,
                    content=line_content,
                )
            )

    return scanned_files, lines


def collect_git_history_lines(repo_root: Path) -> tuple[int, Iterator[SourceLine]]:
    """過去の全コミット履歴（git log --all -p）から追加行を収集する。

    コミットログの Author / Committer メタデータ行は一切収集せず、
    パッチ内で追加されたコンテンツ行（'+' で始まる行）のみを検査対象とする。
    """
    rev_list = subprocess.run(
        ["git", "-C", str(repo_root), "rev-list", "--all", "--count"],
        capture_output=True,
        text=True,
        check=False,
    )
    commit_count = int(rev_list.stdout.strip()) if rev_list.returncode == 0 and rev_list.stdout.strip().isdigit() else 0
    if commit_count == 0:
        return 0, iter(())

    def _history_generator() -> Iterator[SourceLine]:
        # format:COMMIT:<hash> のみを出力し、Author/Committerヘッダは出力自体から除外する
        proc = subprocess.Popen(
            [
                "git",
                "-C",
                str(repo_root),
                "log",
                "--all",
                "--format=COMMIT:%H",
                "-p",
                "--no-color",
                "--unified=0",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        assert proc.stdout is not None

        current_commit = ""
        current_file = ""
        current_line_no = 0
        skip_file = False

        hunk_re_import = __import__("re").compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

        for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            if line.startswith("COMMIT:"):
                current_commit = line[7:].strip()
                continue
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                skip_file = _is_excluded_path(current_file)
                continue
            if skip_file:
                continue
            if line.startswith("@@ "):
                m = hunk_re_import.match(line)
                if m:
                    current_line_no = int(m.group(1))
                continue
            if line.startswith("+") and not line.startswith("+++"):
                yield SourceLine(
                    source_type="GIT_HISTORY",
                    commit_hash=current_commit[:12] if current_commit else "unknown",
                    file_path=current_file,
                    line_number=current_line_no,
                    content=line[1:],
                )
                current_line_no += 1

        proc.wait()

    return commit_count, _history_generator()
