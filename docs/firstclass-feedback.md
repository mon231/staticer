# Feedback for the `firstclass` PyPI package (v0.2.1)

Notes from using `firstclass` in `staticer` (see `staticer/common/depgraph.py`).
Not bugs in `staticer` — observations about the library itself, surfaced
during Task 1's code review.

## Validation is a silent no-op for plain Python-typed fields

`@firstclass.firstclass` advertises "validated when an instance is created
and on every attribute assignment," but for fields annotated with plain
Python types that aren't one of `firstclass`'s own binary-layout types
(`str`, `bool`, `pathlib.Path`, `List[str]`, etc.), `resolve_spec()` maps the
field to a no-op `Plain` spec whose `check()` just returns the value
unchanged (confirmed by reading `_specs.py`). So a class like:

```python
@firstclass
class DependencyNode:
    name: str
    path: Path
    embeddable: bool
    imports: List[str] = field(default_factory=list)
```

gets none of the decorator's validation value — it behaves exactly like a
plain `@dataclass` for every field here, silently. Someone adopting
`firstclass` specifically for its validation, expecting it to reject a
wrong-typed value the way the binary-codec path would, gets no error and no
indication that validation didn't apply.

**Suggestion:** either validate plain-Python-typed fields too (at least a
basic `isinstance` check against the annotation), or make the no-op case
visible — a debug-mode warning, or a `strict=True` kwarg that raises at
class-definition time if any field resolves to the inert `Plain` spec. Right
now the gap is only discoverable by reading `_specs.py`.

## `order=True` default adds unused surface for non-binary use

The decorator defaults to `order=True`, generating `__lt__`/`__le__`/`__gt__`/
`__ge__` that compare all fields tuple-wise — including fields like
`pathlib.Path` or `List[str]` that have no obviously meaningful ordering for
most use cases. For a class used purely as an in-process data holder (no
serialization, no need to sort instances), this is silent extra surface with
no corresponding benefit.

**Suggestion:** consider defaulting `order` to `False` (matching stdlib
`dataclasses`' own default) rather than inverting it, or at least calling
out the inversion more prominently in the docstring/README — right now it's
a one-line mention in the decorator's docstring, easy to miss when skimming
for a drop-in `@dataclass` replacement.
