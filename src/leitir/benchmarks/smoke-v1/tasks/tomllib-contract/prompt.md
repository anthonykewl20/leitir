Target Python 3.11.9 and the standard-library `tomllib` API. Implement `read_project(text)` in `candidate.py`.

Parse TOML text supplied as `str`. Return a new dictionary containing exactly `name`, `requires_python`, and `dependencies` from the `[project]` table. `name` and `requires-python` must be strings and `dependencies` must be a list of strings; otherwise raise `ValueError`. Return a fresh dependency list. Preserve `tomllib` parse failures rather than accepting malformed or duplicate TOML keys.
