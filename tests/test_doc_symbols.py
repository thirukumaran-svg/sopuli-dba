"""Every file path and every docstring cross-reference names something that exists.

Tier 0: reads Markdown and Python source, and imports the package's own modules to
look names up. Nothing connects.

Files move and functions are renamed, and a reference to the old name keeps
reading as correct. Two kinds are checked here:

* **a repository path in backticks**, such as `tests/test_doc_lists.py` or
  `../docs/design/03-json-output.md`. A token counts as a path when it starts with a
  top-level directory of the repository, starts with `../`, or contains a `/` and
  ends in a file extension. It may be written from the repository root, from the
  file it is in, or from `src/` or `src/sopuli/`, which is how the design
  documents name modules. A token with a placeholder in it (`<name>`, `*`, `{x}`)
  is a pattern, not a path, and is skipped.
* **a Sphinx role in a docstring or comment**: :func:, :class:, :data:, :meth:,
  :attr:, :mod:, :exc: and :const:. The target is looked up the way Sphinx would:
  in the module, then in the class the reference is written in, then as a builtin,
  then as a dotted import. A module that cannot be imported here, because it needs
  an install extra, is skipped rather than failed.

A plain backticked name such as `common_options` is not checked, because nothing
tells it apart from a configuration key or a column name.
"""

from __future__ import annotations

import ast
import builtins
import importlib
import importlib.util
import inspect
import re
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from repo_files import requires_repo

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

#: Where references are looked for. `CHANGELOG.md` is history, and is left out.
SCANNED = ("docs", "src", "tests", "test", "examples")
ROOT_FILES = ("README.md", "CLAUDE.md", "CONTRIBUTING.md")

# ------------------------------------------------------------------- paths ---

TOP_LEVEL = ("src/", "tests/", "test/", "docs/", "sql/", "examples/", ".github/", "../")
EXTENSION = re.compile(r"\.(py|md|sql|ya?ml|json|toml|txt|cfg|ini)$")
BACKTICKED = re.compile(r"`+([^`\s]+)`+")
NOT_A_PATH = re.compile(r"[<>*{}$%|?]|://|^[~/\-]|^\./")


def _scanned_files(*suffixes: str) -> list[Path]:
    files = [ROOT / name for name in ROOT_FILES]
    for directory in SCANNED:
        for suffix in suffixes:
            files += sorted((ROOT / directory).rglob(f"*{suffix}"))
    return [path for path in files if path.is_file() and path.suffix in suffixes]


def _path_tokens(line: str) -> Iterator[str]:
    for match in BACKTICKED.finditer(line):
        token = match.group(1).rstrip(".,:;)")
        if NOT_A_PATH.search(token):
            continue
        if token.startswith(TOP_LEVEL) or ("/" in token and EXTENSION.search(token)):
            # `file.py:120` and `doc.md#anchor` name the file.
            yield re.split(r"[#:]", token)[0]


def _path_exists(token: str, written_in: Path) -> bool:
    bases = (ROOT, written_in.parent, SRC, SRC / "sopuli")
    return any((base / token).exists() for base in bases)


def test_every_backticked_path_exists() -> None:
    requires_repo(ROOT / "docs")
    missing = [
        f"{path.relative_to(ROOT).as_posix()}:{number}: `{token}`"
        for path in _scanned_files(".md", ".py")
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        for token in _path_tokens(line)
        if not _path_exists(token, path)
    ]
    assert not missing, "\n".join(missing)


@pytest.mark.parametrize(
    ("line", "tokens"),
    [
        ("see `tests/test_doc_lists.py:12`", ["tests/test_doc_lists.py"]),
        ("in `../docs/design/03-json-output.md#2`.", ["../docs/design/03-json-output.md"]),
        ("module `config/targets.py`", ["config/targets.py"]),
        ("`sopuli-run-<v>.schema.json`, `~/.vault-token`, `./sopuli.yaml`", []),
        ("a key, `vaults.*.addr`, and a word, `creds`", []),
    ],
)
def test_what_counts_as_a_path(line: str, tokens: list[str]) -> None:
    assert list(_path_tokens(line)) == tokens


# ------------------------------------------------------------------- roles ---

ROLE = re.compile(r":(?:func|class|data|meth|attr|mod|exc|const):`~?([^`<>]+?)(?:\s*<([^>]+)>)?`")


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(SRC).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


@cache
def _assigned_on_self(cls: type) -> frozenset[str]:
    """Attributes a class sets as ``self.name = ...``, which only exist on an instance."""
    try:
        tree = ast.parse(inspect.getsource(cls).lstrip())
    except (OSError, TypeError, SyntaxError, IndentationError):
        return frozenset()
    return frozenset(
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.ctx, ast.Store)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    )


def _has(obj: Any, name: str) -> bool:
    if hasattr(obj, name):
        return True
    if inspect.isclass(obj):
        return any(
            name in getattr(cls, "__annotations__", {}) or name in _assigned_on_self(cls)
            for cls in obj.__mro__
        )
    return False


def _walk(obj: Any, parts: list[str]) -> bool:
    for part in parts:
        if not _has(obj, part):
            return False
        obj = getattr(obj, part, None)
    return True


@cache
def _declared_dependencies() -> frozenset[str]:
    """The import names of what `pyproject.toml` declares, extras included."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    declared = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        declared += extra
    return frozenset(re.split(r"[<>=!~\[; ]", name, maxsplit=1)[0] for name in declared)


def _imported(dotted: str) -> bool | None:
    """Whether ``dotted`` names something importable.

    ``None`` where the module it starts in is a declared dependency that is not
    installed here -- the docs lane installs no extras -- since its absence says
    nothing about the reference. Any other missing module is a wrong name.
    """
    parts = dotted.split(".")
    for split in range(len(parts), 0, -1):
        try:
            module = importlib.import_module(".".join(parts[:split]))
        except ModuleNotFoundError as error:
            if error.name in _declared_dependencies():
                return None
            if split == 1:
                return False
            continue
        except ImportError:
            return None
        return _walk(module, parts[split:])
    return False


def _enclosing_classes(tree: ast.Module) -> list[tuple[int, int, list[str]]]:
    """(first line, last line, qualified name parts) for every class in a module."""
    found: list[tuple[int, int, list[str]]] = []

    def visit(node: ast.AST, outer: list[str]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                qualified = [*outer, child.name]
                found.append((child.lineno, child.end_lineno or child.lineno, qualified))
                visit(child, qualified)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, outer)

    visit(tree, [])
    return found


def _resolves_in_source(target: str, module: ModuleType, classes: list[list[str]]) -> bool | None:
    parts = target.split(".")
    if _has(module, parts[0]) and _walk(module, parts):
        return True
    for qualified in classes:
        cls: Any = module
        if _walk(cls, qualified):
            for name in qualified:
                cls = getattr(cls, name)
            if _walk(cls, parts):
                return True
    if hasattr(builtins, parts[0]):
        return _walk(builtins, parts)
    return _imported(target)


def _source_roles() -> Iterator[tuple[str, int, str, bool | None]]:
    for path in sorted((SRC / "sopuli").rglob("*.py")):
        name = _module_name(path)
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue  # needs an extra this environment has not got
        package = name if path.name == "__init__.py" else name.rpartition(".")[0]
        text = path.read_text(encoding="utf-8")
        classes = _enclosing_classes(ast.parse(text))
        for number, line in enumerate(text.splitlines(), 1):
            for match in ROLE.finditer(line):
                target = (match.group(2) or match.group(1)).strip()
                if target.startswith("."):
                    target = importlib.util.resolve_name(target, package)
                around = [
                    qualified for first, last, qualified in classes if first <= number <= last
                ]
                yield (
                    path.relative_to(ROOT).as_posix(),
                    number,
                    match.group(0),
                    _resolves_in_source(target, module, around),
                )


@dataclass(frozen=True)
class _Scope:
    """What a test module's top level binds: imported names to what they import,
    and the names it defines itself, with the class bodies kept."""

    imported: dict[str, str]
    classes: dict[str, ast.ClassDef]
    others: frozenset[str]


def _module_scope(tree: ast.Module) -> _Scope:
    imported: dict[str, str] = {}
    classes: dict[str, ast.ClassDef] = {}
    others: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    imported[alias.asname] = alias.name
                else:
                    head = alias.name.split(".")[0]
                    imported[head] = head
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                imported[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.ImportFrom):
            # `from repo_files import x` style relative helpers have no package.
            others.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.ClassDef):
            classes[node.name] = node
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            others.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                others.update(
                    name.id
                    for name in ast.walk(target)
                    if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Store)
                )
    return _Scope(imported, classes, frozenset(others))


def _class_members(node: ast.ClassDef) -> set[str]:
    """What a class body binds, and what its methods set as ``self.name``."""
    members: set[str] = set()
    for child in node.body:
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            members.add(child.name)
        elif isinstance(child, (ast.Assign, ast.AnnAssign)):
            targets = child.targets if isinstance(child, ast.Assign) else [child.target]
            members.update(
                name.id
                for target in targets
                for name in ast.walk(target)
                if isinstance(name, ast.Name)
            )
    for each in ast.walk(node):
        if (
            isinstance(each, ast.Attribute)
            and isinstance(each.ctx, ast.Store)
            and isinstance(each.value, ast.Name)
            and each.value.id == "self"
        ):
            members.add(each.attr)
    return members


def _resolves_in_test(target: str, scope: _Scope, around: list[str]) -> bool | None:
    """Look ``target`` up the way Sphinx would from inside a test module.

    ``None`` where the answer depends on something this cannot see, such as a
    member inherited from a base class defined outside the module or an
    attribute of an instance.
    """
    head, *rest = target.split(".")
    if head in ("tests", "test"):
        return (ROOT / Path(*target.split("."))).with_suffix(".py").exists()
    if around and not rest and head in _class_members(scope.classes[around[0]]):
        return True
    if head in scope.imported:
        return _imported(".".join([scope.imported[head], *rest]))
    if head in scope.classes:
        if not rest:
            return True
        node = scope.classes[head]
        if rest[0] in _class_members(node):
            return True if len(rest) == 1 else None
        for base in node.bases:
            name = ast.unparse(base).split(".")[0]
            if name in scope.imported:
                dotted = ast.unparse(base).replace(name, scope.imported[name], 1)
                return _imported(".".join([dotted, *rest]))
        return None if node.bases else False
    if head in scope.others:
        return True if not rest else None
    if hasattr(builtins, head):
        return _walk(builtins, [head, *rest])
    return _imported(target)


def _test_roles() -> Iterator[tuple[str, int, str, bool | None]]:
    """Test modules are not a package, so their names are read from the source
    rather than imported. A `tests.` module path is checked as a file."""
    for path in sorted([*(ROOT / "tests").rglob("*.py"), *(ROOT / "test").rglob("*.py")]):
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        scope = _module_scope(tree)
        classes = [(first, last, qualified) for first, last, qualified in _enclosing_classes(tree)]
        for number, line in enumerate(text.splitlines(), 1):
            for match in ROLE.finditer(line):
                target = (match.group(2) or match.group(1)).strip()
                # The outermost class the line sits in, if it is a module-level one.
                around = [
                    qualified[0]
                    for first, last, qualified in classes
                    if first <= number <= last and qualified[0] in scope.classes
                ][:1]
                found = _resolves_in_test(target, scope, around)
                yield path.relative_to(ROOT).as_posix(), number, match.group(0), found


def test_every_docstring_reference_resolves() -> None:
    unresolved = [
        f"{file}:{number}: {role}"
        for file, number, role, found in [*_source_roles(), *_test_roles()]
        if found is False
    ]
    assert not unresolved, "\n".join(unresolved)


def test_the_role_lookup_tells_a_real_name_from_a_missing_one() -> None:
    """The scan passing proves nothing if every lookup came back ``None``."""
    module = importlib.import_module("sopuli.config.errors")

    assert _resolves_in_source("KeyPath", module, []) is True
    assert _resolves_in_source("ConfigError.source", module, []) is True
    assert _resolves_in_source("datetime.datetime", module, []) is True
    assert _resolves_in_source("NoSuchName", module, []) is False
    assert _imported("sopuli.config.errors.KeyPath") is True
    assert _imported("sopuli.config.errors.NoSuchName") is False


def test_a_test_module_reference_is_walked_to_its_end() -> None:
    """A member of a class, or of something imported, is checked as well as the
    name it starts with."""
    tree = ast.parse(
        "from sopuli.config.errors import ConfigError as Bad\n"
        "class Transport:\n"
        "    def request(self):\n"
        "        local = 1\n"
        "        self.sent = local\n"
    )
    scope = _module_scope(tree)

    assert _resolves_in_test("Transport.request", scope, []) is True
    assert _resolves_in_test("Transport.sent", scope, []) is True
    assert _resolves_in_test("Transport.no_such_method", scope, []) is False
    assert _resolves_in_test("Bad.source", scope, []) is True
    assert _resolves_in_test("Bad.no_such_attribute", scope, []) is False
    assert _resolves_in_test("local", scope, []) is False
    assert _resolves_in_test("request", scope, ["Transport"]) is True
