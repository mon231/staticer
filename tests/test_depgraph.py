from pathlib import Path

import pytest

from staticer.common.depgraph import (
    DependencyNode,
    CyclicDependencyError,
    build_dependency_graph,
    embed_order,
)


def _fake(imports_by_name, resolvable_paths):
    def list_imports(path):
        return imports_by_name[path.name]

    def resolve(name, search_dirs):
        return resolvable_paths.get(name)

    return list_imports, resolve


# ---------------------------------------------------------------------------
# build_dependency_graph
# ---------------------------------------------------------------------------


def test_excludes_by_name():
    # root -> A (excluded by name)
    root = Path("root.exe")
    list_imports, resolve = _fake(
        imports_by_name={"root.exe": ["a.dll"], "a.dll": []},
        resolvable_paths={"a.dll": Path("/libs/a.dll")},
    )

    graph = build_dependency_graph(root, list_imports, resolve, [], None, {"a.dll"})

    assert graph["a.dll"].embeddable is False


def test_exclusion_propagates_transitively():
    # root -> X (excluded), root -> Y, X -> Y
    # Y must end up NOT embeddable even though root also imports it directly,
    # regardless of which edge to Y is visited first.
    root = Path("root.exe")
    list_imports, resolve = _fake(
        imports_by_name={
            "root.exe": ["x.dll", "y.dll"],
            "x.dll": ["y.dll"],
            "y.dll": [],
        },
        resolvable_paths={
            "x.dll": Path("/libs/x.dll"),
            "y.dll": Path("/libs/y.dll"),
        },
    )

    graph = build_dependency_graph(root, list_imports, resolve, [], None, {"x.dll"})

    assert graph["y.dll"].embeddable is False


def test_exclusion_propagates_transitively_regardless_of_visit_order():
    # Same scenario as above, but root visits Y before X, so the direct
    # (non-excluded) edge to Y is discovered first.
    root = Path("root.exe")
    list_imports, resolve = _fake(
        imports_by_name={
            "root.exe": ["y.dll", "x.dll"],
            "x.dll": ["y.dll"],
            "y.dll": [],
        },
        resolvable_paths={
            "x.dll": Path("/libs/x.dll"),
            "y.dll": Path("/libs/y.dll"),
        },
    )

    graph = build_dependency_graph(root, list_imports, resolve, [], None, {"x.dll"})

    assert graph["y.dll"].embeddable is False


def test_exclusion_cascades_through_already_visited_node():
    # root -> a.dll -> b.dll -> c.dll   (a.dll visited first, not excluded)
    # root -> x.dll -> b.dll            (x.dll excluded)
    #
    # c.dll is reachable ONLY through b.dll, which is reachable both via the
    # non-excluded a.dll and via the excluded x.dll. Because a.dll is visited
    # first, b.dll (and therefore c.dll) is initially recorded as embeddable;
    # when x.dll's subtree later re-reaches the already-visited b.dll and
    # excludes it, that exclusion must cascade down into b.dll's own already
    # -recorded import (c.dll) too -- not stop one hop short.
    root = Path("root.exe")
    list_imports, resolve = _fake(
        imports_by_name={
            "root.exe": ["a.dll", "x.dll"],
            "a.dll": ["b.dll"],
            "x.dll": ["b.dll"],
            "b.dll": ["c.dll"],
            "c.dll": [],
        },
        resolvable_paths={
            "a.dll": Path("/libs/a.dll"),
            "x.dll": Path("/libs/x.dll"),
            "b.dll": Path("/libs/b.dll"),
            "c.dll": Path("/libs/c.dll"),
        },
    )

    graph = build_dependency_graph(root, list_imports, resolve, [], None, {"x.dll"})

    assert graph["b.dll"].embeddable is False
    assert graph["c.dll"].embeddable is False


def test_exclusion_cascades_to_sibling_import_discovered_after_a_cycle():
    # root -> a.dll -> [b.dll, d.dll]  (a.dll imports b.dll FIRST, then d.dll)
    #         b.dll -> c.dll
    #         c.dll -> a.dll            (cycle back to a.dll)
    #         c.dll excluded by name
    #
    # Visiting c.dll (excluded) re-visits the already-in-progress a.dll
    # before a.dll's own import loop has reached d.dll yet -- that re-visit
    # must cascade a.dll's new exclusion into b.dll (already recorded)
    # correctly, but the real regression is d.dll: a.dll's own loop reads
    # a.dll's exclusion state fresh on each iteration, so the *not-yet-
    # visited* d.dll (processed only after the cascade from the cycle has
    # already excluded a.dll) must also come out excluded -- not stay
    # embeddable because the loop captured a stale "not excluded" flag
    # from before the cascade happened.
    root = Path("root.exe")
    list_imports, resolve = _fake(
        imports_by_name={
            "root.exe": ["a.dll"],
            "a.dll": ["b.dll", "d.dll"],
            "b.dll": ["c.dll"],
            "c.dll": ["a.dll"],
            "d.dll": [],
        },
        resolvable_paths={
            "a.dll": Path("/libs/a.dll"),
            "b.dll": Path("/libs/b.dll"),
            "c.dll": Path("/libs/c.dll"),
            "d.dll": Path("/libs/d.dll"),
        },
    )

    graph = build_dependency_graph(root, list_imports, resolve, [], None, {"c.dll"})

    assert graph["a.dll"].embeddable is False
    assert graph["b.dll"].embeddable is False
    assert graph["d.dll"].embeddable is False


def test_lib_dir_scopes_embedding():
    # root -> A (path inside lib_dir), root -> B (path outside lib_dir)
    root = Path("root.exe")
    lib_dir = Path("/libs")
    list_imports, resolve = _fake(
        imports_by_name={"root.exe": ["a.dll", "b.dll"], "a.dll": [], "b.dll": []},
        resolvable_paths={
            "a.dll": Path("/libs/a.dll"),
            "b.dll": Path("/other/b.dll"),
        },
    )

    graph = build_dependency_graph(root, list_imports, resolve, [], lib_dir, set())

    assert graph["a.dll"].embeddable is True
    assert graph["b.dll"].embeddable is False


def test_unresolved_import_is_left_dynamic():
    # root imports "missing.dll", resolve() returns None for it
    root = Path("root.exe")
    list_imports, resolve = _fake(
        imports_by_name={"root.exe": ["missing.dll"]},
        resolvable_paths={},
    )

    graph = build_dependency_graph(root, list_imports, resolve, [], None, set())

    assert "missing.dll" not in graph  # never embedded, never an error


# ---------------------------------------------------------------------------
# embed_order
# ---------------------------------------------------------------------------


def test_embed_order_is_dependencies_first():
    # A embeddable, B embeddable, A imports B -> B must come before A
    graph = {
        "b.dll": DependencyNode(name="b.dll", path=Path("/libs/b.dll"), embeddable=True),
        "a.dll": DependencyNode(
            name="a.dll", path=Path("/libs/a.dll"), embeddable=True, imports=["b.dll"]
        ),
    }

    order = embed_order(graph)

    assert order.index(graph["b.dll"]) < order.index(graph["a.dll"])


def test_embed_order_skips_non_embeddable_nodes():
    graph = {
        "excluded.dll": DependencyNode(
            name="excluded.dll", path=Path("/libs/excluded.dll"), embeddable=False
        ),
        "a.dll": DependencyNode(name="a.dll", path=Path("/libs/a.dll"), embeddable=True),
    }

    order = embed_order(graph)

    assert graph["excluded.dll"] not in order
    assert graph["a.dll"] in order


def test_embed_order_raises_on_cycle():
    # A imports B, B imports A, both embeddable
    graph = {
        "a.dll": DependencyNode(
            name="a.dll", path=Path("/libs/a.dll"), embeddable=True, imports=["b.dll"]
        ),
        "b.dll": DependencyNode(
            name="b.dll", path=Path("/libs/b.dll"), embeddable=True, imports=["a.dll"]
        ),
    }

    with pytest.raises(CyclicDependencyError):
        embed_order(graph)


def test_embed_order_cycle_error_names_the_cycle():
    graph = {
        "a.dll": DependencyNode(
            name="a.dll", path=Path("/libs/a.dll"), embeddable=True, imports=["b.dll"]
        ),
        "b.dll": DependencyNode(
            name="b.dll", path=Path("/libs/b.dll"), embeddable=True, imports=["a.dll"]
        ),
    }

    with pytest.raises(CyclicDependencyError) as exc_info:
        embed_order(graph)

    message = str(exc_info.value)
    assert "a.dll" in message
    assert "b.dll" in message


# ---------------------------------------------------------------------------
# embed_order(graph, allow_cycles=True) -- cycle-tolerant opt-in path
# ---------------------------------------------------------------------------


def test_embed_order_allow_cycles_groups_two_node_cycle():
    # Same shape as test_embed_order_raises_on_cycle, but opted into the
    # cycle-tolerant path: both nodes must still come out, grouped adjacent
    # to each other, with no exception raised.
    graph = {
        "a.dll": DependencyNode(
            name="a.dll", path=Path("/libs/a.dll"), embeddable=True, imports=["b.dll"]
        ),
        "b.dll": DependencyNode(
            name="b.dll", path=Path("/libs/b.dll"), embeddable=True, imports=["a.dll"]
        ),
    }

    order = embed_order(graph, allow_cycles=True)

    assert len(order) == 2
    assert graph["a.dll"] in order
    assert graph["b.dll"] in order
    # Grouped adjacent to each other (the whole order has only these two
    # nodes here, so this is trivially true, but assert it explicitly).
    assert abs(order.index(graph["a.dll"]) - order.index(graph["b.dll"])) == 1


def test_embed_order_allow_cycles_groups_three_node_cycle():
    # a -> b -> c -> a: a genuine 3-node cycle, not just the 2-node case.
    graph = {
        "a.dll": DependencyNode(
            name="a.dll", path=Path("/libs/a.dll"), embeddable=True, imports=["b.dll"]
        ),
        "b.dll": DependencyNode(
            name="b.dll", path=Path("/libs/b.dll"), embeddable=True, imports=["c.dll"]
        ),
        "c.dll": DependencyNode(
            name="c.dll", path=Path("/libs/c.dll"), embeddable=True, imports=["a.dll"]
        ),
    }

    order = embed_order(graph, allow_cycles=True)

    assert len(order) == 3
    for n in ("a.dll", "b.dll", "c.dll"):
        assert graph[n] in order
    indices = [order.index(graph[n]) for n in ("a.dll", "b.dll", "c.dll")]
    # All three must be grouped adjacent to each other (contiguous indices).
    assert sorted(indices) == [min(indices), min(indices) + 1, min(indices) + 2]


def test_embed_order_allow_cycles_non_cyclic_node_depends_on_cycle():
    # d.dll (not part of any cycle) imports a.dll, which is part of the
    # a.dll <-> b.dll cycle. d.dll must still come out ordered correctly
    # AFTER the whole cycle it depends on (dependencies-first between the
    # cycle's SCC and the rest of the graph), even though no single order
    # exists *within* the cycle itself.
    graph = {
        "a.dll": DependencyNode(
            name="a.dll", path=Path("/libs/a.dll"), embeddable=True, imports=["b.dll"]
        ),
        "b.dll": DependencyNode(
            name="b.dll", path=Path("/libs/b.dll"), embeddable=True, imports=["a.dll"]
        ),
        "d.dll": DependencyNode(
            name="d.dll", path=Path("/libs/d.dll"), embeddable=True, imports=["a.dll"]
        ),
    }

    order = embed_order(graph, allow_cycles=True)

    assert len(order) == 3
    for n in ("a.dll", "b.dll", "d.dll"):
        assert graph[n] in order
    assert order.index(graph["a.dll"]) < order.index(graph["d.dll"])
    assert order.index(graph["b.dll"]) < order.index(graph["d.dll"])
    # The cycle's own two members still land adjacent to each other.
    assert abs(order.index(graph["a.dll"]) - order.index(graph["b.dll"])) == 1


def test_embed_order_allow_cycles_still_orders_acyclic_part_correctly():
    # No cycle at all: allow_cycles=True must still produce the same
    # dependencies-first guarantee as the strict default for a purely
    # acyclic graph.
    graph = {
        "b.dll": DependencyNode(name="b.dll", path=Path("/libs/b.dll"), embeddable=True),
        "a.dll": DependencyNode(
            name="a.dll", path=Path("/libs/a.dll"), embeddable=True, imports=["b.dll"]
        ),
    }

    order = embed_order(graph, allow_cycles=True)

    assert order.index(graph["b.dll"]) < order.index(graph["a.dll"])


def test_embed_order_allow_cycles_still_skips_non_embeddable_nodes():
    graph = {
        "excluded.dll": DependencyNode(
            name="excluded.dll", path=Path("/libs/excluded.dll"), embeddable=False
        ),
        "a.dll": DependencyNode(name="a.dll", path=Path("/libs/a.dll"), embeddable=True),
    }

    order = embed_order(graph, allow_cycles=True)

    assert graph["excluded.dll"] not in order
    assert graph["a.dll"] in order
