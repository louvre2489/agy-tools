"""単一責任: 正規表現でマッチした候補文字列の妥当性検証（誤検知除外）を行うモジュール。"""

import ipaddress
import re

# ダミー値やプレースホルダとみなすキーワード
_PLACEHOLDER_PATTERNS = (
    "example",
    "dummy",
    "sample",
    "your_",
    "your-",
    "<your",
    "xxxx",
    "****",
    "changeme",
    "todo",
    "placeholder",
    "test_key",
    "test-key",
    "fake",
    "mock",
    "123456",
    "abcdef",
)

# 除外するダミー・予約メールドメイン
_IGNORED_EMAIL_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "localhost",
    "invalid",
    "users.noreply.github.com",
)

# コード作者・著作権・コミット署名を示す行パターン（大文字小文字区別なし）
_AUTHOR_SIGNATURE_LINE_RE = re.compile(
    r"(?i)(?:"
    r"@(?:author|maintainer|contributor|copyright|license)\b"
    r"|\b(?:author|authors|maintainer|maintainers|contributor|contributors|created\s+by|written\s+by|modified\s+by|coded\s+by|developed\s+by)\b\s*[:=\[{]?"
    r"|\b(?:__author__|__email__|__maintainer__|__credits__|author_email|maintainer_email)\b"
    r"|\b(?:signed-off-by|co-authored-by|reviewed-by|acked-by|reported-by|tested-by|suggested-by|committer|commit)\s*:"
    r"|\bcopyright\b|\(c\)|©|all\s+rights\s+reserved"
    r"|(?:作成者|著者|作者|開発者|考案者|メンテナ|署名|著作権)\s*[:：=]?"
    r")"
)

# コメント行内の `<email@domain>` または `(email@domain)` 形式の作者署名パターン
_COMMENT_ANGLE_EMAIL_RE = re.compile(
    r"^\s*(?:#|//|/\*+|\*+|<!--|--|;)\s*[^<\n]{1,60}<[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,18}>"
)


def is_not_placeholder(matched_value: str, _line: str = "") -> bool:
    """マッチした値が明らかなプレースホルダや環境変数参照でないかを検証する。"""
    val = matched_value.strip().strip("\"'`")
    if not val or len(val) < 6:
        return False
    # 変数展開 (${VAR}, $VAR, {{VAR}}) は除外
    if val.startswith(("$", "{{", "%(")) or val.endswith("}}"):
        return False
    lower_val = val.lower()
    return not any(token in lower_val for token in _PLACEHOLDER_PATTERNS)


def is_valid_credit_card(matched_value: str, _line: str = "") -> bool:
    """Luhnアルゴリズムおよび同一数字の連続除外によりクレジットカード番号を検証する。"""
    digits_only = re.sub(r"[\s-]", "", matched_value)
    if not digits_only.isdigit() or not (13 <= len(digits_only) <= 19):
        return False
    # 全て同じ数字や単純な連番・テスト番号は除外
    if len(set(digits_only)) <= 2:
        return False

    total = 0
    reverse_digits = digits_only[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def is_public_ipv4(matched_value: str, line: str = "") -> bool:
    """プライベートIP、ループバック、予約済みIP、またはバージョン番号表記を除外しグローバルIPv4のみを判定する。"""
    # バージョン番号表記 (例: v1.2.3.4 や version = "1.2.3.4") の誤検知を抑制
    lower_line = line.lower()
    idx = line.find(matched_value)
    if idx > 0 and line[idx - 1] in ("v", "V", "/"):
        return False
    if "version" in lower_line and "ip" not in lower_line and "host" not in lower_line:
        return False

    try:
        ip = ipaddress.IPv4Address(matched_value)
    except ipaddress.AddressValueError:
        return False

    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_author_signature_context(text: str) -> bool:
    """与えられた行または直近の文脈テキストがコード作者の署名・メタデータを示しているか判定する。"""
    if not text:
        return False
    return bool(_AUTHOR_SIGNATURE_LINE_RE.search(text) or _COMMENT_ANGLE_EMAIL_RE.search(text))


def is_sensitive_email(matched_value: str, line: str = "") -> bool:
    """コード内のメールアドレスからダミードメインやコード作者の署名等を除外する。"""
    lower_val = matched_value.lower().strip()
    if "@" not in lower_val:
        return False
    local_part, domain = lower_val.rsplit("@", 1)
    if domain in _IGNORED_EMAIL_DOMAINS or domain.endswith(".example.com"):
        return False
    if any(p in local_part for p in ("example", "test", "dummy", "noreply", "no-reply", "sample")):
        return False
    # コード作者を示す署名（@author, Author:, Copyright, Signed-off-by:, author_email 等）は除外
    if is_author_signature_context(line):
        return False
    return True
