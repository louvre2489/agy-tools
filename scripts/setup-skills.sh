#!/usr/bin/env bash
set -euo pipefail

# 単一責任: リポジトリ内の skills ディレクトリ配下の各スキルを ~/.gemini/config/skills にシンボリックリンクとして配置する。

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SKILLS_SRC_DIR="${REPO_ROOT}/skills"
SKILLS_DEST_DIR="${HOME}/.gemini/config/skills"

# 共通シンボリックリンク作成モジュールの読み込み
# shellcheck source=scripts/lib/symlink.sh
source "${SCRIPT_DIR}/lib/symlink.sh"

setup_skills() {
  echo "=== Skills のセットアップを開始します ==="

  if [[ ! -d "$SKILLS_SRC_DIR" ]]; then
    echo "[ERROR] スキル格納ディレクトリが見つかりません: $SKILLS_SRC_DIR" >&2
    return 1
  fi

  mkdir -p "$SKILLS_DEST_DIR"

  local has_error=0
  local skill_count=0

  for skill_path in "${SKILLS_SRC_DIR}"/*; do
    # ディレクトリが存在しない場合（空の場合）のガード
    [[ -e "$skill_path" ]] || continue
    # ディレクトリのみをスキルとして対象にする
    [[ -d "$skill_path" ]] || continue

    local skill_name
    skill_name="$(basename "$skill_path")"
    local target_link="${SKILLS_DEST_DIR}/${skill_name}"

    skill_count=$((skill_count + 1))
    if ! create_safe_symlink "$skill_path" "$target_link"; then
      has_error=1
    fi
  done

  if [[ "$skill_count" -eq 0 ]]; then
    echo "[INFO] 配置対象のスキルがありませんでした。"
  fi

  if [[ "$has_error" -ne 0 ]]; then
    echo "=== Skills のセットアップが一部の警告/スキップを伴い終了しました ===" >&2
    return 1
  fi

  echo "=== Skills のセットアップが正常に完了しました ==="
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  setup_skills
fi
