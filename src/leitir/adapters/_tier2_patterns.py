from __future__ import annotations

import re

EXPORT_FUNCTION = re.compile(
    r"^\s*export\s+(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*(\([^\r\n{};]*\)(?:\s*:\s*[^={;]+)?)"
)
EXPORT_CLASS = re.compile(
    r"^\s*export\s+(?:default\s+)?class\s+([A-Za-z_$][\w$]*)(?:\s+extends\s+([^\r\n{]+))?\s*\{?"
)
EXPORT_VALUE = re.compile(
    r"^\s*export\s+(?:declare\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*([^=;]+))?\s*=\s*(.*)$"
)
ARROW = re.compile(
    r"^(?:async\s+)?(\([^\r\n{};]*\)|[A-Za-z_$][\w$]*)(?:\s*:\s*[^=]+)?\s*=>"
)
FUNCTION_VALUE = re.compile(
    r"^(?:async\s+)?function(?:\s+[A-Za-z_$][\w$]*)?\s*(\([^\r\n{};]*\))"
)
CLASS_METHOD = re.compile(
    r"^\s*(?:(?:public|protected|private|static|abstract|override|readonly|async|get|set)\s+)*"
    r"([A-Za-z_$][\w$]*|constructor)\s*(\([^\r\n{};]*\)(?:\s*:\s*[^={;]+)?)\s*(?:\{|;)?\s*$"
)


def mask_comments_and_strings(content: str) -> str:
    result = list(content)
    index = 0
    state = "code"
    quote = ""
    while index < len(content):
        char = content[index]
        following = content[index + 1] if index + 1 < len(content) else ""
        if state == "code":
            if char == "/" and following == "/":
                result[index] = " "
                result[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if char == "/" and following == "*":
                result[index] = " "
                result[index + 1] = " "
                index += 2
                state = "block_comment"
                continue
            if char in {"'", '"', "`"}:
                result[index] = " "
                quote = char
                state = "string"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                result[index] = " "
        elif state == "block_comment":
            if char == "*" and following == "/":
                result[index] = " "
                result[index + 1] = " "
                index += 2
                state = "code"
                continue
            if char != "\n":
                result[index] = " "
        else:
            if char == "\\":
                result[index] = " "
                if following:
                    if following != "\n":
                        result[index + 1] = " "
                    index += 2
                    continue
            elif char == quote:
                result[index] = " "
                state = "code"
            elif char != "\n":
                result[index] = " "
        index += 1
    return "".join(result)
