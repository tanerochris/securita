"""Policy chunking: heading sections, windows, sanitization."""

from security_agent.policy.chunking import chunk_markdown, chunk_pages, clean_text


def test_clean_text_strips_nul_and_crlf():
    assert clean_text("a\x00b\r\nc\x01d") == "ab\ncd"


def test_markdown_splits_on_headings_with_refs():
    text = "# Policy\n\nNever touch openssl.\n\n## Reviews\n\nAuth needs review.\n"
    chunks = chunk_markdown(text, max_chars=2000, overlap=0)
    assert len(chunks) == 2
    assert chunks[0][1] == "## Policy"
    assert "openssl" in chunks[0][0]
    assert chunks[1][1] == "## Reviews"


def test_preamble_chunk_has_no_ref():
    chunks = chunk_markdown("Intro line.\n\n# Head\n\nBody.\n", max_chars=2000, overlap=0)
    assert chunks[0] == ("Intro line.", None)


def test_long_section_windows_with_overlap_and_terminates():
    body = "word " * 2000  # ~10000 chars
    chunks = chunk_markdown(f"# Big\n\n{body}\n", max_chars=2000, overlap=200)
    assert len(chunks) > 3
    assert all(len(text) <= 2000 for text, _ in chunks)
    assert all(ref == "## Big" for _, ref in chunks)
    # Overlap keeps continuity between adjacent windows.
    assert set(chunks[0][0].split()) & set(chunks[1][0].split())


def test_empty_text_yields_no_chunks():
    assert chunk_markdown("   \n  ", max_chars=200, overlap=20) == []
    assert chunk_pages([("page 1", "  ")]) == []


def test_pages_keep_page_refs():
    chunks = chunk_pages([("page 1", "Alpha rule."), ("page 2", "Beta rule.")])
    assert [(ref) for _, ref in chunks] == ["page 1", "page 2"]
