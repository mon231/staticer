"""Format-agnostic dependency graph: resolution, transitive exclusion, and
dependency-first init order, driven entirely by caller-supplied
``list_imports``/``resolve`` callables.

This module knows nothing about PE or ELF; those formats supply their own
``list_imports``/``resolve`` implementations (see ``pe_embedder``/
``elf_embedder``) and call into ``build_dependency_graph``/``embed_order``.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set


@dataclass
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
            node = nodes[name]
            # Only cascade when this visit newly excludes the node (guards
            # against both redundant re-cascading on repeat revisits and,
            # critically, infinite recursion around cycles: once a node is
            # already False, re-walking its recorded imports again is a
            # no-op).
            if is_excluded and node.embeddable:
                node.embeddable = False
                for child_name in node.imports:
                    child = nodes.get(child_name)
                    if child is not None:
                        visit(child_name, child.path, force_excluded=True)
            return
        node = DependencyNode(name=name, path=path, embeddable=not is_excluded)
        nodes[name] = node
        for imp_name in list_imports(path):
            resolved = resolve(imp_name, search_dirs)
            if resolved is None:
                continue
            node.imports.append(imp_name)
            # Deliberately re-read node.embeddable on every iteration rather
            # than reusing the `is_excluded` captured above: a cycle back to
            # this same node (via an earlier import in this same loop) can
            # cascade-exclude it mid-loop, through the `node in nodes`
            # branch below. A still-Imports-to-visit import discovered
            # *after* that cascade must see the now-current exclusion state,
            # not the stale value from before the cascade ran.
            visit(imp_name, resolved, force_excluded=not node.embeddable)

    for imp_name in list_imports(root_path):
        resolved = resolve(imp_name, search_dirs)
        if resolved is not None:
            visit(imp_name, resolved, force_excluded=False)
    return nodes


def embed_order(graph: Dict[str, DependencyNode], allow_cycles: bool = False) -> List[DependencyNode]:
    """Dependencies-first order over the embeddable subset of ``graph``.

    Default (``allow_cycles=False``, unchanged from this function's original
    contract): a strict topological sort. Raises ``CyclicDependencyError``,
    naming the cycle, if a cycle exists among embeddable nodes. Existing
    callers (e.g. ``elf_embedder``) that rely on this strict all-or-nothing
    check keep getting it exactly as before -- this is deliberately an
    additive opt-in, not a change to the default call's behavior.

    ``allow_cycles=True``: tolerate cycles among embeddable nodes instead of
    raising. Nodes are grouped into strongly connected components (via
    Tarjan's algorithm, over the embeddable subgraph) and the returned list
    concatenates every component's nodes, with components themselves in
    dependencies-first order relative to each other (for any edge A -> B
    where A and B land in different components, B's component appears
    before A's) -- the same guarantee the strict path gives for individual
    nodes. Within one multi-node component (an actual cycle), there is by
    definition no single valid order, so its nodes are grouped together,
    adjacent, in whatever deterministic order Tarjan's algorithm discovers
    them (itself fully determined by `graph`'s own iteration order and each
    node's `imports` list order) -- callers that opt into this must already
    be prepared to resolve any cross-dependency needs after every node in
    the group has been placed, as ``pe_embedder.py`` does, rather than
    relying on one group member being fully ready before another is
    processed.
    """
    if not allow_cycles:
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

    order = []
    for component in _tarjan_sccs(graph):
        order.extend(component)
    return order


def _tarjan_sccs(graph: Dict[str, DependencyNode]) -> List[List[DependencyNode]]:
    """Tarjan's strongly-connected-components algorithm over the embeddable
    subset of ``graph``, following each node's ``imports`` edges (A -> B
    meaning "A imports B").

    Returns a list of components (each a list of one or more
    ``DependencyNode``), in an order where, for any edge A -> B crossing
    between two different components, B's component is emitted before A's
    -- i.e. dependencies-first between components, exactly like
    ``embed_order``'s own strict-path guarantee for individual nodes (a
    single-node component is just the degenerate, acyclic case of this same
    property). This falls out of Tarjan's algorithm directly: a component is
    only finalized (popped) once every component reachable from it via an
    outgoing edge has already been finalized, since the DFS recurses into
    those neighbors first.

    A component with more than one node is a genuine cycle with no valid
    single order among its own members; callers needing to tolerate that
    (see ``embed_order(graph, allow_cycles=True)``) must not depend on
    within-component ordering for correctness.
    """
    index_counter = [0]
    indices: Dict[str, int] = {}
    lowlink: Dict[str, int] = {}
    stack: List[str] = []
    on_stack: Set[str] = set()
    sccs: List[List[DependencyNode]] = []

    def strongconnect(name: str) -> None:
        indices[name] = lowlink[name] = index_counter[0]
        index_counter[0] += 1
        stack.append(name)
        on_stack.add(name)

        node = graph[name]
        for imp_name in node.imports:
            dep = graph.get(imp_name)
            if dep is None or not dep.embeddable:
                continue
            if imp_name not in indices:
                strongconnect(imp_name)
                lowlink[name] = min(lowlink[name], lowlink[imp_name])
            elif imp_name in on_stack:
                lowlink[name] = min(lowlink[name], indices[imp_name])

        if lowlink[name] == indices[name]:
            component: List[DependencyNode] = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.append(graph[member])
                if member == name:
                    break
            sccs.append(component)

    for name, node in graph.items():
        if node.embeddable and name not in indices:
            strongconnect(name)

    return sccs
