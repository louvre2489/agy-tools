"""単一責任: 機微情報検出ルールの定義と、行データに対するマッチング処理のみを行うモジュール。"""

from collections import deque
import re
from typing import Iterable

from masker import mask_line_snippet, mask_sensitive_value
from models import DetectionRule, Finding, SourceLine
from validators import (
    is_author_signature_context,
    is_not_placeholder,
    is_public_ipv4,
    is_sensitive_email,
    is_valid_credit_card,
)


def build_detection_rules() -> tuple[DetectionRule, ...]:
    """検査に使用する全検出ルールを構築して返す。"""
    return (
        # --- 1. SSHキー / 秘密鍵 ---
        DetectionRule(
            rule_id="SSH_PRIVATE_KEY",
            category="SSHキー / 秘密鍵",
            description="SSHまたはPEM形式の秘密鍵ヘッダ",
            severity="CRITICAL",
            pattern=re.compile(
                r"(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)"
            ),
            target_group=1,
        ),
        # --- 2. APIトークン / キー ---
        DetectionRule(
            rule_id="AWS_ACCESS_KEY",
            category="APIトークン / キー",
            description="AWS Access Key ID",
            severity="CRITICAL",
            pattern=re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
            target_group=1,
            validator=is_not_placeholder,
        ),
        DetectionRule(
            rule_id="GITHUB_TOKEN",
            category="APIトークン / キー",
            description="GitHub Personal Access Token / App Token",
            severity="CRITICAL",
            pattern=re.compile(
                r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"
            ),
            target_group=1,
        ),
        DetectionRule(
            rule_id="GOOGLE_API_KEY",
            category="APIトークン / キー",
            description="Google Cloud / Firebase API Key",
            severity="CRITICAL",
            pattern=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
            target_group=1,
        ),
        DetectionRule(
            rule_id="SLACK_TOKEN",
            category="APIトークン / キー",
            description="Slack API Token / Webhook",
            severity="CRITICAL",
            pattern=re.compile(
                r"\b(xox[baprs]-[0-9A-Za-z\-]{10,100}|https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)\b"
            ),
            target_group=1,
        ),
        DetectionRule(
            rule_id="AI_PROVIDER_API_KEY",
            category="APIトークン / キー",
            description="OpenAI / Anthropic API Key",
            severity="CRITICAL",
            pattern=re.compile(
                r"\b(sk-ant-[A-Za-z0-9\-_]{20,200}|sk-(?:proj-)?[A-Za-z0-9\-_]{32,200})\b"
            ),
            target_group=1,
            validator=is_not_placeholder,
        ),
        DetectionRule(
            rule_id="GENERIC_API_KEY",
            category="APIトークン / キー",
            description="汎用APIキー・アクセストークン代入",
            severity="HIGH",
            pattern=re.compile(
                r"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9\-_.~+/]{16,128})['\"]"
            ),
            target_group=1,
            validator=is_not_placeholder,
        ),
        # --- 3. シークレット / パスワード ---
        DetectionRule(
            rule_id="GENERIC_SECRET",
            category="シークレット",
            description="シークレットキー・秘密値のハードコード",
            severity="HIGH",
            pattern=re.compile(
                r"(?i)\b(?:aws_secret_access_key|[a-z0-9_]*secret(?:[_-]?key)?|private[_-]?key|jwt[_-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9\-_.~+/=]{12,128})['\"]"
            ),
            target_group=1,
            validator=is_not_placeholder,
        ),
        DetectionRule(
            rule_id="PASSWORD_ASSIGNMENT",
            category="パスワード",
            description="パスワードのハードコード",
            severity="HIGH",
            pattern=re.compile(
                r"(?i)(?:password|passwd|pwd|db_pass|db_password)\s*[:=]\s*['\"]([^'\"\s]{6,128})['\"]"
            ),
            target_group=1,
            validator=is_not_placeholder,
        ),
        DetectionRule(
            rule_id="URI_CREDENTIALS",
            category="パスワード",
            description="接続URI内に埋め込まれた認証情報 (user:password@host)",
            severity="CRITICAL",
            pattern=re.compile(
                r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:([^/\s:@\"'`]{4,100})@[a-zA-Z0-9.-]+"
            ),
            target_group=1,
            validator=is_not_placeholder,
        ),
        # --- 4. 個人情報 (PII) ---
        DetectionRule(
            rule_id="CREDIT_CARD",
            category="個人情報 (クレジットカード番号)",
            description="クレジットカード番号 (Luhn検証済み)",
            severity="CRITICAL",
            pattern=re.compile(
                r"\b((?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|35\d{2})(?:[\s-]?\d{4}){2,3}|\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5})\b"
            ),
            target_group=1,
            validator=is_valid_credit_card,
        ),
        DetectionRule(
            rule_id="MY_NUMBER",
            category="個人情報 (マイナンバー)",
            description="個人番号（マイナンバー）の疑いがある12桁番号",
            severity="CRITICAL",
            pattern=re.compile(
                r"(?i)(?:マイナンバー|個人番号|my[_-]?number)[^\d\n]{0,20}(\d{4}[\s-]?\d{4}[\s-]?\d{4})\b"
            ),
            target_group=1,
        ),
        DetectionRule(
            rule_id="JP_PHONE_NUMBER",
            category="個人情報 (電話番号)",
            description="日本の電話番号（携帯・固定電話）",
            severity="MEDIUM",
            pattern=re.compile(
                r"(?:(?<![\d\-])(0[789]0-\d{4}-\d{4}|0\d{1,4}-\d{1,4}-\d{4})(?![\d\-])|(\+81-\d{1,4}-\d{1,4}-\d{4})(?![\d\-]))"
            ),
            target_group=0,
        ),
        DetectionRule(
            rule_id="JP_ADDRESS",
            category="個人情報 (住所)",
            description="日本の住所表記（都道府県＋市区町村＋番地）",
            severity="MEDIUM",
            pattern=re.compile(
                r"((?:〒\s*\d{3}-\d{4}\s*)?(?:北海道|青森県|岩手県|宮城県|秋田県|山形県|福島県|茨城県|栃木県|群馬県|埼玉県|千葉県|東京都|神奈川県|新潟県|富山県|石川県|福井県|山梨県|長野県|岐阜県|静岡県|愛知県|三重県|滋賀県|京都府|大阪府|兵庫県|奈良県|和歌山県|鳥取県|島根県|岡山県|広島県|山口県|徳島県|香川県|愛媛県|高知県|福岡県|佐賀県|長崎県|熊本県|大分県|宮崎県|鹿児島県|沖縄県)[^\s,、。'\"<>]{2,15}[市区町村郡][^\s,、。'\"<>]*[\d０-９一二三四五六七八九十]+[丁目番地号\-ー−][\d０-９一二三四五六七八九十丁目番地号\-ー−]*)"
            ),
            target_group=1,
        ),
        DetectionRule(
            rule_id="PERSONAL_NAME_FIELD",
            category="個人情報 (氏名)",
            description="氏名フィールドにハードコードされた個人名",
            severity="MEDIUM",
            pattern=re.compile(
                r"(?i)(?:氏名|お名前|フルネーム|full[_-]?name|customer[_-]?name|user[_-]?real[_-]?name)\s*[:=：]\s*['\"]?([一-龥々〆ヵヶ]{1,5}[\s　]+[一-龥々〆ヵヶ]{1,5})['\"]?"
            ),
            target_group=1,
        ),
        DetectionRule(
            rule_id="PUBLIC_IPV4",
            category="個人情報 / インフラ情報 (IPアドレス)",
            description="ハードコードされたグローバルIPv4アドレス",
            severity="MEDIUM",
            pattern=re.compile(
                r"\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\b"
            ),
            target_group=1,
            validator=is_public_ipv4,
        ),
        DetectionRule(
            rule_id="EMAIL_IN_CODE",
            category="個人情報 (コード内メールアドレス)",
            description="ソースコード・設定ファイル内に含まれるメールアドレス",
            severity="MEDIUM",
            pattern=re.compile(
                r"\b([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,18})\b"
            ),
            target_group=1,
            validator=is_sensitive_email,
        ),
    )


def scan_lines(
    lines: Iterable[SourceLine],
    rules: tuple[DetectionRule, ...],
) -> list[Finding]:
    """与えられた行ストリームに対して全検出ルールを適用し、重複を排除した検出結果リストを返す。"""
    findings: list[Finding] = []
    seen_keys: set[tuple[str, str, str, int, str]] = set()
    recent_lines_by_file: dict[tuple[str, str], deque[str]] = {}

    for src_line in lines:
        text = src_line.content
        if not text or len(text) > 4096:
            # 1行が極端に長いミニファイ済み行は正規表現ReDoS防止のためスキップ
            continue

        file_key = (src_line.source_type, src_line.file_path)
        history_window = recent_lines_by_file.setdefault(file_key, deque(maxlen=5))
        context_text = "\n".join((*history_window, text))
        history_window.append(text)

        for rule in rules:
            for match in rule.pattern.finditer(text):
                raw_val = match.group(rule.target_group)
                if not raw_val:
                    continue
                if rule.validator is not None and not rule.validator(raw_val, text):
                    continue
                # 複数行にわたるコード作者署名ブロック（package.json の author や複数行コメントの Author 等）内のメアドは結果に出力しない
                if rule.rule_id == "EMAIL_IN_CODE" and is_author_signature_context(context_text):
                    continue

                masked_val = mask_sensitive_value(raw_val)
                dedup_key = (
                    rule.rule_id,
                    src_line.source_type,
                    src_line.file_path,
                    src_line.line_number,
                    masked_val,
                )
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        description=rule.description,
                        severity=rule.severity,
                        source_type=src_line.source_type,
                        commit_hash=src_line.commit_hash,
                        file_path=src_line.file_path,
                        line_number=src_line.line_number,
                        masked_value=masked_val,
                        masked_line_snippet=mask_line_snippet(text, raw_val),
                    )
                )

    return findings
