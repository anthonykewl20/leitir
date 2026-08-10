from __future__ import annotations

import ast


def parse_python(content: str, filename: str = "<unknown>") -> ast.Module:
    return ast.parse(content, filename=filename)


def python_unparse(node: ast.AST | None) -> str | None:
    return ast.unparse(node) if node is not None else None


def python_argument(
    argument: ast.arg, default: ast.expr | None = None
) -> str:
    rendered = argument.arg
    annotation = python_unparse(argument.annotation)
    if annotation is not None:
        rendered += f": {annotation}"
    if default is not None:
        rendered += f" = {ast.unparse(default)}"
    return rendered


def python_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    arguments = node.args
    positional = list(arguments.posonlyargs) + list(arguments.args)
    defaults: list[ast.expr | None] = [None] * (
        len(positional) - len(arguments.defaults)
    ) + list(arguments.defaults)
    parts = [
        python_argument(argument, default)
        for argument, default in zip(positional, defaults, strict=False)
    ]
    if arguments.posonlyargs:
        parts.insert(len(arguments.posonlyargs), "/")
    if arguments.vararg is not None:
        parts.append("*" + python_argument(arguments.vararg))
    elif arguments.kwonlyargs:
        parts.append("*")
    for argument, default in zip(
        arguments.kwonlyargs, arguments.kw_defaults, strict=False
    ):
        parts.append(python_argument(argument, default))
    if arguments.kwarg is not None:
        parts.append("**" + python_argument(arguments.kwarg))
    signature = f"({', '.join(parts)})"
    returns = python_unparse(node.returns)
    return signature + (f" -> {returns}" if returns is not None else "")
