from __future__ import annotations

from dataclasses import dataclass

from ._interfaces import ArtifactStore


@dataclass(frozen=True)
class LineageNode:
    path: str
    classification: str
    depth: int
    sources: list[str]


@dataclass(frozen=True)
class LineageReport:
    root: str
    found: bool
    max_depth: int
    nodes: list[LineageNode]


async def resolve_lineage(store: ArtifactStore, root_path: str, max_depth: int = 10) -> LineageReport:
    root_artifact = await store.get_artifact(root_path)
    if root_artifact is None:
        return LineageReport(root=root_path, found=False, max_depth=0, nodes=[])

    nodes: list[LineageNode] = []
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(root_path, 0)]

    while queue:
        current_path, depth = queue.pop(0)
        if current_path in visited:
            continue
        visited.add(current_path)

        artifact = await store.get_artifact(current_path)
        sources = list(artifact.provenance_chain) if artifact and artifact.provenance_chain else []
        nodes.append(
            LineageNode(
                path=current_path,
                classification=artifact.classification if artifact is not None else "CLEAN",
                depth=depth,
                sources=sources,
            )
        )

        if depth >= max_depth:
            continue

        for source_path in sources:
            if source_path not in visited:
                queue.append((source_path, depth + 1))

    return LineageReport(
        root=root_path,
        found=True,
        max_depth=max((node.depth for node in nodes), default=0),
        nodes=nodes,
    )
