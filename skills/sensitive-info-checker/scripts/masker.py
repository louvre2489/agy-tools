"""単一責任: 検出された機微情報の文字列をポリシーに従ってマスク処理するモジュール。"""


def mask_sensitive_value(raw_value: str) -> str:
    """機微情報の先頭4文字のみを残し、残りを '****' に置換する。

    文字列長が4文字以下の場合は、漏洩防止のため全体を '****' とする。
    """
    stripped = raw_value.strip()
    if len(stripped) <= 4:
        return "****"
    return f"{stripped[:4]}****"


def mask_line_snippet(line: str, raw_value: str, max_length: int = 100) -> str:
    """行スニペット内の機微情報部分をマスクし、長すぎる場合は切り詰める。"""
    masked_val = mask_sensitive_value(raw_value)
    sanitized = line.strip()
    if raw_value and raw_value in sanitized:
        sanitized = sanitized.replace(raw_value, masked_val)
    if len(sanitized) > max_length:
        return f"{sanitized[:max_length]}..."
    return sanitized
