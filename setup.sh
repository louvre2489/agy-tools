#!/usr/bin/env bash
set -euo pipefail

# 単一責任: リポジトリ管理ツールのセットアップ全体のオーケストレーションを行うエントリポイント。
# Skills や Hooks 等の各セットアップスクリプトを順次呼び出す。

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

main() {
  echo "🚀 agy-tools セットアップを開始します..."
  echo ""

  # 1. Skills のセットアップ
  "${REPO_ROOT}/scripts/setup-skills.sh"
  echo ""

  # 2. Hooks のセットアップ
  "${REPO_ROOT}/scripts/setup-hooks.sh"

  echo ""
  echo "✅ すべてのセットアップが完了しました。"
}

main "$@"
