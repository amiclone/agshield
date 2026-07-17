"""Tests for the safe human-speed baseline model."""

from agshield.human_baseline import STEPS, run_human_baseline


def test_human_baseline_is_reproducible_without_executing_commands():
    slept = []
    result = run_human_baseline(1, seed=2026, sleep=slept.append)

    assert result["mode"] == "human_baseline"
    assert len(result["actions"]) == len(STEPS)
    assert [round(value, 4) for value in slept] == [
        action["planned_delay_seconds"] for action in result["actions"]
    ]
    assert result["planned_duration_seconds"] == round(
        sum(round(value, 4) for value in slept), 4
    )


def test_human_baseline_seed_repeats_planned_duration():
    first = run_human_baseline(1, seed=7, sleep=lambda _: None)
    second = run_human_baseline(2, seed=7, sleep=lambda _: None)

    assert first["planned_duration_seconds"] == second["planned_duration_seconds"]
