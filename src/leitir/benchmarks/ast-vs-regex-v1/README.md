# Python AST versus regex comparison v1

`comparison.json` compares line-span sets returned by `PythonAstAdapter` and
`PythonAdapter` for every Python task in the pinned `search-v1` manifest. The
vendored corpus blob is byte-checked against the Git blob SHA pinned by that
manifest before measurement.

`agreement` is intersection over union. AST-versus-regex precision uses AST
spans as the denominator, while recall uses regex spans. The pin metrics compare
each adapter with the expected spans in `search-v1`; those pins are incomplete
relevance judgments and are not a complete Python-search quality corpus.

Reproduce or verify the artifact from the repository root:

```console
PYTHONPATH=src python benchmarks/compare_python_adapters.py
PYTHONPATH=src python benchmarks/compare_python_adapters.py --check
```

This artifact is measurement-only and does not select either adapter as the
default.
