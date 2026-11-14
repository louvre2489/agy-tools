#!/usr/bin/env bash
set -euo pipefail

# 単一責任: リポジトリ管理ツールのセットアップ全体のオーケストレーションを行うエントリポイント。
# 今後 skills 以外の管理対象（rules, workflows 等）が増えた場合は、ここから各セットアップスクリプトを呼び出す。

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

main() {
  echo "🚀 agy-tools セットアップを開始します..."
  echo ""

  # 1. Skills のセットアップ
  "${REPO_ROOT}/scripts/setup-skills.sh"

  echo ""
  echo "✅ すべてのセットアップが完了しました。"
}

main "$@"
