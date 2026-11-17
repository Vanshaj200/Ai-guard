import pytest
from scanner import _probe_groups

EXPECTED_FAMILIES = {
    "DIRECT_INJECTION",
    "CONTENT_INJECTION",
    "DATA_EXFILTRATION",
    "GOAL_DIVERSION",
    "MEMORY_POISONING",
    "AUTONOMOUS_ACTIONS",
    "PLANNING_MANIPULATION",
    "TOOL_MANIPULATION",
}


@pytest.mark.asyncio
async def test_probe_groups_loading():
    groups = await _probe_groups()
    categories = {cat for cat, _ in groups}

    # All 8 attack families from the bundled datasets are present
    assert EXPECTED_FAMILIES <= categories

    # Every family has at least one probe, and probes are listed per family
    for cat, probes in groups:
        assert isinstance(probes, list)
        if cat in EXPECTED_FAMILIES:
            assert len(probes) > 0

    # The built-in dataset has 50 probes in total
    built_in = sum(len(p) for cat, p in groups if cat in EXPECTED_FAMILIES)
    assert built_in >= 50
