#!/usr/bin/env bash
set -euo pipefail

# 単一責任: リポジトリ内の hooks 設定 (hooks.json) およびフックスクリプトディレクトリを ~/.gemini/config 配下にシンボリックリンクとして配置する。

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOOKS_SRC_DIR="${REPO_ROOT}/hooks"
CONFIG_DEST_DIR="${HOME}/.gemini/config"

# 共通シンボリックリンク作成モジュールの読み込み
# shellcheck source=scripts/lib/symlink.sh
source "${SCRIPT_DIR}/lib/symlink.sh"

setup_hooks() {
  echo "=== Hooks のセットアップを開始します ==="

  if [[ ! -d "$HOOKS_SRC_DIR" ]]; then
    echo "[ERROR] フック格納ディレクトリが見つかりません: $HOOKS_SRC_DIR" >&2
    return 1
  fi

  mkdir -p "$CONFIG_DEST_DIR"

  local has_error=0

  # 1. hooks.json のシンボリックリンク作成
  if ! create_safe_symlink "${HOOKS_SRC_DIR}/hooks.json" "${CONFIG_DEST_DIR}/hooks.json"; then
    has_error=1
  fi

  # 2. フックスクリプト群 (~/.gemini/config/hooks -> hooks/scripts) のシンボリックリンク作成
  if ! create_safe_symlink "${HOOKS_SRC_DIR}/scripts" "${CONFIG_DEST_DIR}/hooks"; then
    has_error=1
  fi

  if [[ "$has_error" -ne 0 ]]; then
    echo "=== Hooks のセットアップが一部の警告/スキップを伴い終了しました ===" >&2
    return 1
  fi

  echo "=== Hooks のセットアップが正常に完了しました ==="
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  setup_hooks
fi
