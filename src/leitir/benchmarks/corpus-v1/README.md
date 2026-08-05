# Corpus benchmark v1

`manifest.json` defines the versioned corpus fetch-correctness benchmark shipped
with leitir. Its tasks pin package or repository specifications to expected
source repositories, commits, and file content.

The live benchmark requires network access and remains disabled unless
`LEITIR_ENABLE_LIVE_E2E=1` is set explicitly.
