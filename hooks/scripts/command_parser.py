"""単一責任: シェルコマンド文字列を解析し、git commit の実行有無と対象リポジトリパス群を特定するモジュール。"""

from pathlib import Path
import re
import shlex

# シェルの複合コマンド区切りパターン (&&, ||, ;, |, 改行)
_COMMAND_SPLIT_RE = re.compile(r"(?:&&|\|\||[;|\n])+|\bsudo\b")

# 引数を1つ取る git グローバルオプション
_GIT_OPTIONS_WITH_VALUE = ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path")


def extract_git_commit_targets(command_line: str, default_cwd: str) -> list[Path]:
    """コマンドライン文字列から `git commit` の実行対象ディレクトリ一覧を抽出する。

    `git commit` が含まれない場合は空リスト `[]` を返す。
    複合コマンド (`cd /path && git add . && git commit -m "..."` や `git -C /path commit`) にも対応する。
    """
    if not command_line or "commit" not in command_line:
        return []

    base_dir = Path(default_cwd).expanduser() if default_cwd else Path.cwd()
    current_dir = base_dir
    targets: list[Path] = []

    for segment in _COMMAND_SPLIT_RE.split(command_line):
        tokens = _tokenize_segment(segment)
        if not tokens:
            continue

        # 先頭のサブシェル括弧や環境変数代入 (KEY=VAL) をスキップ
        tokens = _strip_leading_env_and_parens(tokens)
        if not tokens:
            continue

        cmd = tokens[0]
        # cd コマンドによるディレクトリ移動を追跡
        if cmd == "cd" and len(tokens) >= 2:
            cd_target = Path(tokens[1]).expanduser()
            current_dir = (current_dir / cd_target) if not cd_target.is_absolute() else cd_target
            continue

        # git コマンドかどうか判定
        if cmd == "git" or cmd.endswith("/git"):
            is_commit, repo_dir = _parse_git_tokens(tokens[1:], current_dir)
            if is_commit and repo_dir not in targets:
                targets.append(repo_dir)

    return targets


def _tokenize_segment(segment: str) -> list[str]:
    """1つのコマンドセグメントをトークン分割する（クォート不整合時は空白分割にフォールバック）。"""
    stripped = segment.strip()
    if not stripped:
        return []
    try:
        return shlex.split(stripped, posix=True)
    except ValueError:
        return stripped.split()


def _strip_leading_env_and_parens(tokens: list[str]) -> list[str]:
    """先頭の `(` や `VAR=val` 形式の環境変数指定を取り除く。"""
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx].lstrip("(")
        if not tok:
            idx += 1
            continue
        if "=" in tok and not tok.startswith("-") and tok.split("=", 1)[0].isidentifier():
            idx += 1
            continue
        tokens[idx] = tok
        return tokens[idx:]
    return []


def _parse_git_tokens(git_args: list[str], current_dir: Path) -> tuple[bool, Path]:
    """git の引数リストを走査し、サブコマンドが `commit` かどうかと `-C` 適用後のパスを返す。"""
    repo_dir = current_dir
    i = 0
    while i < len(git_args):
        arg = git_args[i].rstrip(")")
        if not arg:
            i += 1
            continue

        # `-C <path>` の処理
        if arg == "-C" and i + 1 < len(git_args):
            c_path = Path(git_args[i + 1]).expanduser()
            repo_dir = (repo_dir / c_path) if not c_path.is_absolute() else c_path
            i += 2
            continue

        # `-C<path>` のように結合されている場合
        if arg.startswith("-C") and len(arg) > 2:
            c_path = Path(arg[2:]).expanduser()
            repo_dir = (repo_dir / c_path) if not c_path.is_absolute() else c_path
            i += 1
            continue

        # その他の値を伴う git グローバルオプション (`-c key=val` 等)
        if arg in _GIT_OPTIONS_WITH_VALUE:
            i += 2
            continue

        # `--git-dir=...` などの `=` 付きオプションまたは単体フラグ (`--no-pager` 等)
        if arg.startswith("-"):
            i += 1
            continue

        # 最初の非オプション引数が git サブコマンド
        return (arg == "commit"), repo_dir

    return False, repo_dir
