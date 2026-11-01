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
