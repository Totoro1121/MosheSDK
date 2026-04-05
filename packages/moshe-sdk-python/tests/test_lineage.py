from __future__ import annotations

import pytest

from moshe import MemoryStore, resolve_lineage
from moshe._store import ArtifactRecord


@pytest.mark.asyncio
async def test_resolve_lineage_missing_root() -> None:
    report = await resolve_lineage(MemoryStore(), "missing.txt")
    assert report.found is False
    assert report.nodes == []


@pytest.mark.asyncio
async def test_resolve_lineage_single_node() -> None:
    store = MemoryStore()
    await store.put_artifact("root.txt", ArtifactRecord("root.txt", "TAINTED", "seed", "seed", "t1", "t1", []))
    report = await resolve_lineage(store, "root.txt")
    assert report.found is True
    assert len(report.nodes) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("chain_length", [2, 3])
async def test_resolve_lineage_bfs(chain_length: int) -> None:
    store = MemoryStore()
    await store.put_artifact("a", ArtifactRecord("a", "TAINTED", "seed", "seed", "t1", "t1", ["b"]))
    await store.put_artifact("b", ArtifactRecord("b", "TAINTED", "seed", "seed", "t1", "t1", ["c"] if chain_length == 3 else []))
    if chain_length == 3:
        await store.put_artifact("c", ArtifactRecord("c", "TAINTED", "seed", "seed", "t1", "t1", []))
    report = await resolve_lineage(store, "a")
    assert len(report.nodes) == chain_length


@pytest.mark.asyncio
async def test_resolve_lineage_handles_cycles() -> None:
    store = MemoryStore()
    await store.put_artifact("a", ArtifactRecord("a", "TAINTED", "seed", "seed", "t1", "t1", ["b"]))
    await store.put_artifact("b", ArtifactRecord("b", "TAINTED", "seed", "seed", "t1", "t1", ["a"]))
    report = await resolve_lineage(store, "a")
    assert len(report.nodes) == 2


@pytest.mark.asyncio
async def test_resolve_lineage_max_depth_truncates() -> None:
    store = MemoryStore()
    await store.put_artifact("a", ArtifactRecord("a", "TAINTED", "seed", "seed", "t1", "t1", ["b"]))
    await store.put_artifact("b", ArtifactRecord("b", "TAINTED", "seed", "seed", "t1", "t1", ["c"]))
    await store.put_artifact("c", ArtifactRecord("c", "TAINTED", "seed", "seed", "t1", "t1", []))
    report = await resolve_lineage(store, "a", max_depth=1)
    assert len(report.nodes) == 2


@pytest.mark.asyncio
async def test_unknown_paths_appear_as_clean_terminals() -> None:
    store = MemoryStore()
    await store.put_artifact("a", ArtifactRecord("a", "TAINTED", "seed", "seed", "t1", "t1", ["missing"]))
    report = await resolve_lineage(store, "a")
    assert report.nodes[-1].classification == "CLEAN"


@pytest.mark.asyncio
async def test_default_max_depth_is_10() -> None:
    store = MemoryStore()
    for index in range(12):
        next_link = [f"n{index + 1}"] if index < 11 else []
        await store.put_artifact(f"n{index}", ArtifactRecord(f"n{index}", "TAINTED", "seed", "seed", "t1", "t1", next_link))
    report = await resolve_lineage(store, "n0")
    assert len(report.nodes) == 11
