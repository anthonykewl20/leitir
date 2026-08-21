"""Tag-aware default donor discovery resolution (issue #189, ADR-001 P5).

Discovery must pin candidate donors to immutable release tags by default:
``GitHubCodeSearchTransport.resolve_default_pin`` resolves the latest stable
tag (name + dereferenced commit SHA) and only falls back to a default-branch
HEAD pin — labeled non-immutable — when no stable tag is found within the
bounded tag crawl. All fixtures
drive the real transport against a routed local HTTP server (real sockets,
real ``urllib``), never a mock object.
"""

from __future__ import annotations

import re

import pytest
from _http_server import json_body, routed_server

from leitir.discovery_search import (
    CodeSearchError,
    GitHubCodeSearchTransport,
    latest_stable_tag_name,
)

SLUG = "acme/donor"
FIXED_CLOCK = "2026-08-19T00:00:00+00:00"

# Contract fixture: stable tags v1.0.0..v2.3.0 plus prereleases and noise.
PEELED_V2_3_0 = "c" * 39 + "1"
TAG_OBJECT_V2_3_0 = "d" * 39 + "2"
HEAD_SHA = "e" * 39 + "3"
PEELED_V1_0_0 = "f" * 39 + "4"


def _tag_entry(name: str, sha: str) -> dict[str, object]:
    return {
        "name": name,
        "commit": {
            "sha": sha,
            "url": f"https://api.github.com/repos/{SLUG}/commits/{sha}",
        },
    }


TAGS_WITH_STABLES = [
    _tag_entry("v1.0.0", PEELED_V1_0_0),
    _tag_entry("v1.0.0-rc.1", "a" * 40),
    _tag_entry("v1.1.0", "0" * 39 + "1"),
    _tag_entry("v2.0.0", "0" * 39 + "2"),
    _tag_entry("v2.2.0", "0" * 39 + "3"),
    _tag_entry("containment-rootfs-v1", "0" * 39 + "4"),
    _tag_entry("2026.08", "0" * 39 + "5"),
    _tag_entry("latest", "0" * 39 + "6"),
    # v2.3.0 is annotated: the list already carries the peeled commit SHA.
    _tag_entry("v2.3.0", PEELED_V2_3_0),
    # Higher semver, but a prerelease: must never be selected (SP-3).
    _tag_entry("v2.4.0-rc.1", "b" * 40),
]

TAGS_PRERELEASE_ONLY = [
    _tag_entry("v0.1.0-rc.1", "a" * 40),
    _tag_entry("v0.1.0-beta.2", "b" * 40),
]


def _routes(tags: list[dict[str, object]]) -> dict[str, tuple[int, dict[str, str], bytes]]:
    """Routes for a repo whose latest stable tag is the annotated v2.3.0."""
    return {
        f"/repos/{SLUG}/tags": (200, {"Content-Type": "application/json"}, json_body(tags)),
        f"/repos/{SLUG}/git/ref/tags/v2.3.0": (
            200,
            {"Content-Type": "application/json"},
            json_body(
                {
                    "ref": "refs/tags/v2.3.0",
                    "object": {"type": "tag", "sha": TAG_OBJECT_V2_3_0},
                }
            ),
        ),
        f"/repos/{SLUG}/git/tags/{TAG_OBJECT_V2_3_0}": (
            200,
            {"Content-Type": "application/json"},
            json_body(
                {
                    "tag": "v2.3.0",
                    "object": {"type": "commit", "sha": PEELED_V2_3_0},
                }
            ),
        ),
        f"/repos/{SLUG}/commits": (
            200,
            {"Content-Type": "application/json"},
            json_body([{"sha": HEAD_SHA}]),
        ),
    }


def _transport(base_url: str) -> GitHubCodeSearchTransport:
    return GitHubCodeSearchTransport(
        base_url=base_url,
        raw_base_url=base_url,
        sleeper=None,
        clock=lambda: FIXED_CLOCK,
    )


class TestLatestStableTagName:
    """Pure ordering rule: semver-descending, stable-before-prerelease."""

    def test_prefers_highest_stable_version(self):
        names = [entry["name"] for entry in TAGS_WITH_STABLES]
        assert isinstance(names[0], str)
        assert latest_stable_tag_name(names) == "v2.3.0"

    def test_prereleases_are_never_selected(self):
        assert latest_stable_tag_name(["v1.0.0", "v2.0.0-rc.1"]) == "v1.0.0"
        assert latest_stable_tag_name(["v2.4.0-rc.1", "v2.4.0-rc.2"]) is None

    def test_optional_v_prefix_is_accepted(self):
        assert latest_stable_tag_name(["1.9.0", "v2.0.0"]) == "v2.0.0"
        assert latest_stable_tag_name(["V3.0.0", "v2.9.9"]) == "V3.0.0"

    def test_non_semver_and_partial_semver_names_are_ignored(self):
        assert latest_stable_tag_name(["latest", "2026.08", "v1.2", "release-1.2.3"]) is None

    def test_equal_versions_tie_break_on_name_deterministically(self):
        assert latest_stable_tag_name(["v2.3.0", "2.3.0"]) == "2.3.0"
        assert latest_stable_tag_name(["2.3.0", "v2.3.0"]) == "2.3.0"

    def test_selection_is_independent_of_input_order(self):
        import random

        names = [str(entry["name"]) for entry in TAGS_WITH_STABLES]
        expected = latest_stable_tag_name(names)
        for seed in (0, 1, 42, 99999):
            shuffled = list(names)
            random.Random(seed).shuffle(shuffled)
            assert latest_stable_tag_name(shuffled) == expected

    def test_empty_input_yields_none(self):
        assert latest_stable_tag_name([]) is None


class TestResolveDefaultPin:
    """Transport-level default discovery resolution against a real server."""

    def test_default_resolution_pins_latest_stable_tag(self):
        with routed_server(_routes(TAGS_WITH_STABLES)) as server:
            transport = _transport(server.base_url)
            pin = transport.resolve_default_pin(SLUG)
        assert pin.slug == SLUG
        assert pin.ref_kind == "tag"
        assert pin.ref_name == "v2.3.0"
        # AC-1: the SHA is the peeled commit, never the annotated tag object.
        assert pin.commit_sha == PEELED_V2_3_0
        assert pin.commit_sha != TAG_OBJECT_V2_3_0
        assert pin.immutable is True
        described = pin.describe()
        assert "v2.3.0" in described
        assert PEELED_V2_3_0 in described
        assert "immutable" in described

    def test_annotated_tag_peel_chain_is_bounded_and_ordered(self):
        with routed_server(_routes(TAGS_WITH_STABLES)) as server:
            transport = _transport(server.base_url)
            transport.resolve_default_pin(SLUG)
            paths = server.state.request_paths
        assert paths[0] == f"/repos/{SLUG}/tags"
        assert f"/repos/{SLUG}/git/ref/tags/v2.3.0" in paths
        assert f"/repos/{SLUG}/git/tags/{TAG_OBJECT_V2_3_0}" in paths
        # list tags + get ref + one dereference for the annotated tag.
        assert len(paths) == 3

    def test_lightweight_tag_costs_two_api_calls(self):
        routes = _routes(TAGS_WITH_STABLES)
        routes[f"/repos/{SLUG}/git/ref/tags/v2.3.0"] = (
            200,
            {"Content-Type": "application/json"},
            json_body(
                {
                    "ref": "refs/tags/v2.3.0",
                    "object": {"type": "commit", "sha": PEELED_V2_3_0},
                }
            ),
        )
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            pin = transport.resolve_default_pin(SLUG)
            paths = server.state.request_paths
        assert pin.commit_sha == PEELED_V2_3_0
        assert paths == [f"/repos/{SLUG}/tags", f"/repos/{SLUG}/git/ref/tags/v2.3.0"]

    def test_no_tags_repo_falls_back_to_head_labeled_non_immutable(self):
        routes = _routes([])
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            pin = transport.resolve_default_pin(SLUG)
            paths = server.state.request_paths
        assert pin.ref_kind == "head"
        assert pin.ref_name == "HEAD"
        assert pin.commit_sha == HEAD_SHA
        assert pin.immutable is False
        described = pin.describe()
        assert "HEAD" in described
        assert HEAD_SHA in described
        assert "non-immutable" in described
        assert f"/repos/{SLUG}/commits" in paths

    def test_head_fallback_announcement_states_the_crawl_window_bound(self):
        """P3 remediation (PR #214 review): the announcement is honest.

        The tag crawl is bounded (3 pages x 100 tags), so the fallback must
        not claim the repository has "no stable release tags" — stable tags
        beyond the window are simply never seen. The rendered line pins the
        exact bound (300 = TAG_PAGE_SIZE x MAX_TAG_PAGES); if the constants
        change, this expectation must be re-validated deliberately.
        """
        with routed_server(_routes([])) as server:
            transport = _transport(server.base_url)
            pin = transport.resolve_default_pin(SLUG)
        assert pin.describe() == (
            f"HEAD commit {HEAD_SHA} "
            f"(non-immutable: no stable release tag found within the crawl "
            f"window (first 300 tags); resolved {FIXED_CLOCK})"
        )

    def test_prerelease_only_repo_falls_back_to_head(self):
        with routed_server(_routes(TAGS_PRERELEASE_ONLY)) as server:
            transport = _transport(server.base_url)
            pin = transport.resolve_default_pin(SLUG)
        assert pin.ref_kind == "head"
        assert pin.commit_sha == HEAD_SHA
        assert pin.immutable is False

    def test_same_repo_state_resolves_to_the_same_pin(self):
        with routed_server(_routes(TAGS_WITH_STABLES)) as server:
            transport = _transport(server.base_url)
            first = transport.resolve_default_pin(SLUG)
            second = transport.resolve_default_pin(SLUG)
        assert first == second

    def test_pin_carries_human_ref_and_forty_char_sha(self):
        with routed_server(_routes(TAGS_WITH_STABLES)) as server:
            transport = _transport(server.base_url)
            pin = transport.resolve_default_pin(SLUG)
        assert re.fullmatch(r"[0-9a-f]{40}", pin.commit_sha)
        assert pin.ref_name.strip() == pin.ref_name and pin.ref_name


class TestSadPaths:
    """Fail-closed malformed/unpeeled tag handling (SP-1/SP-2)."""

    def test_unreachable_repo_is_a_typed_error(self):
        routes = _routes(TAGS_WITH_STABLES)
        routes[f"/repos/{SLUG}/tags"] = (404, {}, b"")
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            with pytest.raises(CodeSearchError):
                transport.resolve_default_pin(SLUG)

    def test_non_list_tag_payload_is_a_typed_error(self):
        routes = _routes(TAGS_WITH_STABLES)
        routes[f"/repos/{SLUG}/tags"] = (
            200,
            {"Content-Type": "application/json"},
            json_body({"unexpected": "object"}),
        )
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            with pytest.raises(CodeSearchError, match="malformed tag"):
                transport.resolve_default_pin(SLUG)

    def test_non_dict_tag_entry_is_a_typed_error(self):
        routes = _routes(TAGS_WITH_STABLES)
        routes[f"/repos/{SLUG}/tags"] = (
            200,
            {"Content-Type": "application/json"},
            json_body(["v2.3.0"]),
        )
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            with pytest.raises(CodeSearchError, match="malformed tag"):
                transport.resolve_default_pin(SLUG)

    def test_tag_entry_missing_name_is_a_typed_error(self):
        routes = _routes(TAGS_WITH_STABLES)
        routes[f"/repos/{SLUG}/tags"] = (
            200,
            {"Content-Type": "application/json"},
            json_body([{"commit": {"sha": PEELED_V2_3_0}}]),
        )
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            with pytest.raises(CodeSearchError, match="malformed tag"):
                transport.resolve_default_pin(SLUG)

    def test_tag_entry_missing_commit_sha_is_a_typed_error(self):
        routes = _routes(TAGS_WITH_STABLES)
        routes[f"/repos/{SLUG}/tags"] = (
            200,
            {"Content-Type": "application/json"},
            json_body([{"name": "v2.3.0", "commit": {}}]),
        )
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            with pytest.raises(CodeSearchError, match="malformed tag"):
                transport.resolve_default_pin(SLUG)

    def test_non_json_tag_payload_is_a_typed_error(self):
        routes = _routes(TAGS_WITH_STABLES)
        routes[f"/repos/{SLUG}/tags"] = (200, {"Content-Type": "text/html"}, b"<html>")
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            with pytest.raises(CodeSearchError):
                transport.resolve_default_pin(SLUG)

    def test_annotated_tag_that_cannot_be_peeled_is_a_typed_error(self):
        routes = _routes(TAGS_WITH_STABLES)
        routes[f"/repos/{SLUG}/git/tags/{TAG_OBJECT_V2_3_0}"] = (404, {}, b"")
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            with pytest.raises(CodeSearchError):
                transport.resolve_default_pin(SLUG)

    def test_annotated_tag_peeling_to_a_non_commit_is_a_typed_error(self):
        routes = _routes(TAGS_WITH_STABLES)
        routes[f"/repos/{SLUG}/git/tags/{TAG_OBJECT_V2_3_0}"] = (
            200,
            {"Content-Type": "application/json"},
            json_body(
                {
                    "tag": "v2.3.0",
                    "object": {"type": "tree", "sha": "9" * 40},
                }
            ),
        )
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            with pytest.raises(CodeSearchError, match="does not point to a commit"):
                transport.resolve_default_pin(SLUG)

    def test_tag_ref_without_object_is_a_typed_error(self):
        routes = _routes(TAGS_WITH_STABLES)
        routes[f"/repos/{SLUG}/git/ref/tags/v2.3.0"] = (
            200,
            {"Content-Type": "application/json"},
            json_body({"ref": "refs/tags/v2.3.0"}),
        )
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            with pytest.raises(CodeSearchError, match="malformed tag ref"):
                transport.resolve_default_pin(SLUG)

    def test_tag_that_moves_between_list_and_ref_is_rejected(self):
        routes = _routes(TAGS_WITH_STABLES)
        routes[f"/repos/{SLUG}/git/ref/tags/v2.3.0"] = (
            200,
            {"Content-Type": "application/json"},
            json_body(
                {
                    "ref": "refs/tags/v2.3.0",
                    "object": {"type": "commit", "sha": "7" * 40},
                }
            ),
        )
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            with pytest.raises(CodeSearchError, match="moved during resolution"):
                transport.resolve_default_pin(SLUG)


class TestExplicitBranchStillHonored:
    """C-3: an explicitly named branch keeps today's HEAD-of-branch behavior."""

    def test_explicit_branch_resolves_branch_head(self):
        branch_sha = "5" * 39 + "a"
        routes = _routes(TAGS_WITH_STABLES)
        routes[f"/repos/{SLUG}/commits"] = (
            200,
            {"Content-Type": "application/json"},
            json_body([{"sha": branch_sha}]),
        )
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            assert transport.resolve_head_sha(SLUG, "develop") == branch_sha
            paths = server.state.request_paths
        assert paths == [f"/repos/{SLUG}/commits"]


class TestHostPayloadShapeGuards:
    """Issue #204 C-1/AC-1..AC-3, SP-1: hostile host payloads fail typed.

    A buggy or hostile host can serve any JSON shape. Every payload access is
    guarded with a typed ``CodeSearchError`` rejection (the tree.py guarded
    model), so a bare ``AttributeError``/``TypeError`` can never escape the
    module's error taxonomy.
    """

    def _search_routes(self, payload: object) -> dict[str, tuple[int, dict[str, str], bytes]]:
        return {
            "/search/code": (
                200,
                {"Content-Type": "application/json"},
                json_body(payload),
            )
        }

    def test_non_object_code_search_payload_is_a_typed_error(self):
        with routed_server(self._search_routes([])) as server:
            transport = _transport(server.base_url)
            with pytest.raises(
                CodeSearchError,
                match="malformed code search response: expected a JSON object",
            ):
                transport.search("q")

    def test_non_array_items_is_a_typed_error(self):
        payload = {"total_count": 0, "items": {"unexpected": "object"}}
        with routed_server(self._search_routes(payload)) as server:
            transport = _transport(server.base_url)
            with pytest.raises(
                CodeSearchError,
                match="malformed code search response: items must be a JSON array",
            ):
                transport.search("q")

    def test_non_int_total_count_is_a_typed_error(self):
        payload = {"total_count": "12", "items": []}
        with routed_server(self._search_routes(payload)) as server:
            transport = _transport(server.base_url)
            with pytest.raises(
                CodeSearchError,
                match="malformed code search response: total_count must be an integer",
            ):
                transport.search("q")

    def test_boolean_total_count_is_a_typed_error(self):
        # bool is an int subclass in Python but is never an honest total.
        payload = {"total_count": True, "items": []}
        with routed_server(self._search_routes(payload)) as server:
            transport = _transport(server.base_url)
            with pytest.raises(
                CodeSearchError,
                match="total_count must be an integer",
            ):
                transport.search("q")

    def test_non_dict_commit_entry_is_a_typed_error(self):
        routes = {
            f"/repos/{SLUG}/commits": (
                200,
                {"Content-Type": "application/json"},
                json_body(["not-a-dict"]),
            )
        }
        with routed_server(routes) as server:
            transport = _transport(server.base_url)
            with pytest.raises(
                CodeSearchError,
                match=f"malformed commit entry for {SLUG} at HEAD",
            ):
                transport.resolve_head_sha(SLUG)
