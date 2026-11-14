"""単一責任: 機微情報検査で使用するデータ構造（モデル）のみを定義するモジュール。"""

from dataclasses import dataclass
from typing import Callable, Optional, Pattern


@dataclass(frozen=True)
class DetectionRule:
    """単一の機微情報検出ルールを表すデータクラス。"""

    rule_id: str
    category: str
    description: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM"
    pattern: Pattern[str]
    target_group: int = 0
    validator: Optional[Callable[[str, str], bool]] = None


@dataclass(frozen=True)
class SourceLine:
    """検査対象の1行を表すデータクラス。"""

    source_type: str  # "WORKING_TREE" または "GIT_HISTORY"
    commit_hash: Optional[str]
    file_path: str
    line_number: int
    content: str


@dataclass(frozen=True)
class Finding:
    """検出された機微情報の1件を表すデータクラス。"""

    rule_id: str
    category: str
    description: str
    severity: str
    source_type: str
    commit_hash: Optional[str]
    file_path: str
    line_number: int
    masked_value: str
    masked_line_snippet: str


@dataclass(frozen=True)
class ScanSummary:
    """スキャン全体の統計と検出結果一覧を保持するデータクラス。"""

    target_repo: str
    scanned_files_count: int
    scanned_commits_count: int
    findings: tuple[Finding, ...]
