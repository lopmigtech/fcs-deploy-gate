"""`resolve-baseline`: one place that turns a platform's variables into a Baseline ref
(ADR 0002: explicit ref, else merge base in a merge-request pipeline, else previous commit
in a branch pipeline; empty or all-zeros values are unusable)."""

from __future__ import annotations

import io

import pytest

from fcs_deploy_gate import run

ZEROS = "0" * 40
MERGE_BASE = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
PREVIOUS = "fedcba9876543210fedcba9876543210fedcba98"


def resolve(*args: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    code = run(["resolve-baseline", *args], env={}, stdout=stdout, stderr=stderr)
    return code, stdout.getvalue(), stderr.getvalue()


def test_explicit_ref_wins_over_everything() -> None:
    code, out, _ = resolve(
        "--pipeline",
        "merge-request",
        "--explicit-ref",
        "release/2026.10",
        "--merge-base",
        MERGE_BASE,
        "--previous-commit",
        PREVIOUS,
    )

    assert code == 0
    assert out == "ref=release/2026.10\n"


def test_merge_request_pipeline_uses_the_merge_base() -> None:
    code, out, _ = resolve(
        "--pipeline",
        "merge-request",
        "--explicit-ref",
        "",
        "--merge-base",
        MERGE_BASE,
        "--previous-commit",
        PREVIOUS,
    )

    assert code == 0
    assert out == f"ref={MERGE_BASE}\n"


def test_branch_pipeline_uses_the_previous_commit() -> None:
    code, out, _ = resolve(
        "--pipeline",
        "branch",
        "--explicit-ref",
        "",
        "--merge-base",
        "",
        "--previous-commit",
        PREVIOUS,
    )

    assert code == 0
    assert out == f"ref={PREVIOUS}\n"


@pytest.mark.parametrize("unusable", ["", ZEROS], ids=["empty", "forty-zeros"])
def test_first_push_to_a_branch_is_an_error_asking_for_an_explicit_ref(unusable: str) -> None:
    code, out, _ = resolve(
        "--pipeline",
        "branch",
        "--explicit-ref",
        "",
        "--merge-base",
        MERGE_BASE,
        "--previous-commit",
        unusable,
    )

    assert code == 0
    assert out.startswith("error=")
    assert "previous commit" in out
    assert "explicit" in out
    assert "\n" not in out.rstrip("\n")  # one line, fit for $GITHUB_OUTPUT


def test_merge_request_without_a_merge_base_is_an_error() -> None:
    code, out, _ = resolve(
        "--pipeline",
        "merge-request",
        "--explicit-ref",
        "",
        "--merge-base",
        "",
        "--previous-commit",
        PREVIOUS,
    )

    assert code == 0
    assert out.startswith("error=")
    assert "merge base" in out
    assert "explicit" in out


def test_an_all_zeros_explicit_ref_is_unusable_and_falls_through() -> None:
    code, out, _ = resolve(
        "--pipeline",
        "merge-request",
        "--explicit-ref",
        ZEROS,
        "--merge-base",
        MERGE_BASE,
        "--previous-commit",
        "",
    )

    assert code == 0
    assert out == f"ref={MERGE_BASE}\n"


def test_candidates_default_to_empty() -> None:
    code, out, _ = resolve("--pipeline", "branch")

    assert code == 0
    assert out.startswith("error=")


def test_invalid_pipeline_type_exits_2() -> None:
    code, out, err = resolve("--pipeline", "tag")

    assert code == 2
    assert out == ""
    assert "pipeline" in err


@pytest.mark.parametrize(
    "bad", ["abc\ndef=1", "release 2026", "a\tb"], ids=["newline", "space", "tab"]
)
def test_a_candidate_with_whitespace_or_control_characters_exits_2(bad: str) -> None:
    code, out, err = resolve("--pipeline", "branch", "--explicit-ref", bad)

    assert code == 2
    assert out == ""
    assert "explicit-ref" in err
