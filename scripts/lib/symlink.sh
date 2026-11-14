#!/usr/bin/env bash
set -euo pipefail

# 単一責任: 指定されたソースパスからターゲットパスへ安全にシンボリックリンクを作成する。
# - ターゲットが既存のシンボリックリンクである場合は張り直す。
# - ターゲットが実体ファイル/ディレクトリである場合はデータ保護のため上書きせずエラーメッセージを出力してスキップする。
create_safe_symlink() {
  local src_path="$1"
  local dest_path="$2"

  if [[ ! -e "$src_path" ]]; then
    echo "[ERROR] リンク元が存在しません: $src_path" >&2
    return 1
  fi

  # すでにシンボリックリンクが存在する場合は更新（張り直し）
  if [[ -L "$dest_path" ]]; then
    ln -sfn "$src_path" "$dest_path"
    echo "[UPDATED] シンボリックリンクを更新しました: $dest_path -> $src_path"
    return 0
  fi

  # シンボリックリンクではない実体（ディレクトリまたは通常ファイル）が存在する場合は保護（案A）
  if [[ -e "$dest_path" ]]; then
    echo "[SKIP] 実体が存在するため上書きをスキップしました（データ保護）: $dest_path" >&2
    return 1
  fi

  # 新規作成
  ln -s "$src_path" "$dest_path"
  echo "[CREATED] シンボリックリンクを作成しました: $dest_path -> $src_path"
  return 0
}
