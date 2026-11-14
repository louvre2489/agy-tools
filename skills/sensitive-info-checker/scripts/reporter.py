"""単一責任: スキャン結果（ScanSummary）をターミナル出力用のMarkdownレポートに整形するモジュール。"""

from collections import Counter

from models import Finding, ScanSummary


def format_terminal_report(summary: ScanSummary) -> str:
    """検査結果サマリと検出詳細をターミナル向けのMarkdown文字列に整形する。"""
    lines: list[str] = []
    lines.append("# 🔍 機微情報チェックレポート (Sensitive Info Scan Report)")
    lines.append("")
    lines.append("## 📊 スキャン統計")
    lines.append(f"- **対象リポジトリ**: `{summary.target_repo}`")
    lines.append(f"- **検査ファイル数 (Working Tree)**: {summary.scanned_files_count} ファイル")
    lines.append(f"- **検査コミット数 (Git History)**: {summary.scanned_commits_count} コミット（Author/Committerメールアドレスは除外）")
    lines.append(f"- **検出総数**: **{len(summary.findings)} 件**")
    lines.append("")

    if not summary.findings:
        lines.append("✅ **機微な情報は検出されませんでした。**")
        return "\n".join(lines)

    lines.append("⚠️ **機微な情報の可能性がある項目が検出されました！GitHubへプッシュする前に必ず確認・対処してください。**")
    lines.append("")

    # カテゴリ別集計
    category_counts = Counter(f.category for f in summary.findings)
    lines.append("## 📁 カテゴリ別検出件数")
    for category, count in category_counts.most_common():
        lines.append(f"- **{category}**: {count} 件")
    lines.append("")

    # 検出詳細一覧
    lines.append("## 🚨 検出詳細一覧（機微情報は先頭4文字以外マスク済み）")
    lines.append("")
    lines.append("| 重要度 | カテゴリ | 検出箇所 (Source) | ファイルパス : 行番号 | マスク済み検出値 | 行スニペット (マスク済み) |")
    lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")

    for f in _sort_findings(summary.findings):
        source_label = (
            "Working Tree"
            if f.source_type == "WORKING_TREE"
            else f"Commit `{f.commit_hash}`"
        )
        safe_snippet = f.masked_line_snippet.replace("|", "\\|").replace("`", "'")
        lines.append(
            f"| **{f.severity}** | {f.category} | {source_label} | `{f.file_path}:{f.line_number}` | `{f.masked_value}` | `{safe_snippet}` |"
        )

    lines.append("")
    lines.append("## 🛠 推奨される対処アクション")
    lines.append("1. **Working Tree で検出された場合**: 環境変数（`.env` 等＋`.gitignore` 登録）やシークレットマネージャへ移行し、ハードコードされた値を削除してください。")
    lines.append("2. **Git History（過去コミット）で検出された場合**: ファイルを削除して新しいコミットを作るだけでは履歴に残ります。`git filter-repo` 等で履歴から完全に抹消するとともに、**漏洩した可能性のあるキーやトークンは速やかに無効化（ローテーション）**してください。")
    return "\n".join(lines)


def _sort_findings(findings: tuple[Finding, ...]) -> list[Finding]:
    """重要度順（CRITICAL -> HIGH -> MEDIUM）にソートする。"""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    return sorted(
        findings,
        key=lambda f: (
            severity_order.get(f.severity, 99),
            0 if f.source_type == "WORKING_TREE" else 1,
            f.file_path,
            f.line_number,
        ),
    )
