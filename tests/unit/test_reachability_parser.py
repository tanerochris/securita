"""Tree-sitter JS/TS import parser (follow-up #4)."""

import pytest

from security_agent.worker.reachability import analyze, parse_imports


def _specs(source, rel="index.js"):
    return [(s.specifier, s.dynamic_unresolved) for s in parse_imports(source, rel)]


def test_comments_and_strings_do_not_forge_sites():
    source = "// import x from 'evil'\nconst s = \"import y from 'evil2'\";\n/* require('evil3') */"
    assert _specs(source) == []


def test_no_space_and_side_effect_imports():
    assert _specs("import{x}from'pkg-a';\nimport'direct';") == [
        ("pkg-a", False),
        ("direct", False),
    ]


def test_require_resolve_and_concatenated_dynamics_not_silent():
    assert _specs("const a = require.resolve('pkg-c');") == [("pkg-c", False)]
    assert _specs("import('pkg-' + name);") == [("", True)]
    assert _specs("require('pkg-' + name);") == [("", True)]


def test_template_dynamics():
    assert _specs("import(`bare/${x}`);") == [("", True)]
    assert _specs("import(`./rel/${x}`);") == []
    assert _specs("import(`literal-pkg`);") == [("literal-pkg", False)]


def test_reexport_and_escaped_specifier():
    assert _specs("export * as ns from 'pkg-d';") == [("pkg-d", False)]
    assert _specs(r"import x from 'pkg\'s';") == [("pkg's", False)]


def test_garbage_raises_and_analyze_fails_open(tmp_path):
    with pytest.raises(ValueError):
        parse_imports("import x from ; const = (((;", "bad.js")
    (tmp_path / "bad.js").write_text("import x from ; const = (((;")
    (tmp_path / "index.js").write_text("import y from 'pkg-a';")
    graph = analyze(tmp_path)
    assert "bad.js" in graph["fail_open_files"]


def test_typescript_and_tsx_grammars():
    assert _specs("import x from 'pkg-ts';\nconst y: number = 1;", "a.ts") == [("pkg-ts", False)]
    assert _specs("import x from 'pkg-tsx';\nexport const el = <div>{x}</div>;", "a.tsx") == [
        ("pkg-tsx", False)
    ]
