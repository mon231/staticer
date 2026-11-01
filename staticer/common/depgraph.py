"""Format-agnostic dependency graph: resolution, transitive exclusion, and
dependency-first init order, driven entirely by caller-supplied
``list_imports``/``resolve`` callables.

This module knows nothing about PE or ELF; those formats supply their own
``list_imports``/``resolve`` implementations (see ``pe_embedder``/
``elf_embedder``) and call into ``build_dependency_graph``/``embed_order``.
"""

from dataclasses import field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from firstclass import firstclass


@firstclass
class DependencyNode:
    name: str
    path: Path
    embeddable: bool
    # Names of this node's own resolved imports (edges), keyed the same
    # way as the graph dict. Populated by build_dependency_graph;
    # embed_order walks it to produce a dependencies-first order. Not
    # part of the original interface's three fields, but required for
    # embed_order to have any edge information to sort over, since the
    # graph dict is its only input.
    imports: List[str] = field(default_factory=list)


class CyclicDependencyError(Exception):
    pass


def build_dependency_graph(
    root_path: Path,
    list_imports: Callable[[Path], List[str]],
    resolve: Callable[[str, List[Path]], Optional[Path]],
    search_dirs: List[Path],
    lib_dir: Optional[Path],
    exclude: Set[str],
) -> Dict[str, DependencyNode]:
    nodes: Dict[str, DependencyNode] = {}

    def in_scope(path: Path) -> bool:
        return lib_dir is None or path.is_relative_to(lib_dir)

    def visit(name: str, path: Path, force_excluded: bool) -> None:
        is_excluded = force_excluded or (name in exclude) or not in_scope(path)
        if name in nodes:
            if is_excluded:
                nodes[name].embeddable = False
            return
        node = DependencyNode(name=name, path=path, embeddable=not is_excluded)
        nodes[name] = node
        for imp_name in list_imports(path):
            resolved = resolve(imp_name, search_dirs)
            if resolved is None:
                continue
            node.imports.append(imp_name)
            visit(imp_name, resolved, force_excluded=is_excluded)

    for imp_name in list_imports(root_path):
        resolved = resolve(imp_name, search_dirs)
        if resolved is not None:
            visit(imp_name, resolved, force_excluded=False)
    return nodes


def embed_order(graph: Dict[str, DependencyNode]) -> List[DependencyNode]:
    """Dependencies-first topological order over the embeddable subset of
    ``graph``. Raises CyclicDependencyError, naming the cycle, if a cycle
    exists among embeddable nodes."""
    order: List[DependencyNode] = []
    visited: Set[str] = set()
    in_progress: List[str] = []
    in_progress_set: Set[str] = set()

    def visit(name: str) -> None:
        if name in visited:
            return
        if name in in_progress_set:
            cycle = in_progress[in_progress.index(name):] + [name]
            raise CyclicDependencyError(
                "cyclic dependency detected: " + " -> ".join(cycle)
            )

        node = graph[name]
        in_progress.append(name)
        in_progress_set.add(name)

        for imp_name in node.imports:
            dep = graph.get(imp_name)
            if dep is not None and dep.embeddable:
                visit(imp_name)

        in_progress.pop()
        in_progress_set.discard(name)
        visited.add(name)
        order.append(node)

    for name, node in graph.items():
        if node.embeddable:
            visit(name)

    return order
