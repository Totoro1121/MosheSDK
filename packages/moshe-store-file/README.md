# @moshesdk/store-file

Atomic JSON-backed MosheSDK store for single-process persistence.

## Concurrency Contract

This store supports a single writer only in `v0.1.2`. Multiple processes writing to the same backing file path are unsupported.
