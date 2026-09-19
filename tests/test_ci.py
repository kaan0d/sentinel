"""The CI workflow cannot run here, so these tests keep it honest: it must run the commands the
README tells a developer to run, on the Python versions the project claims, and it must run the
tests that need a real interface."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def development_commands() -> list[str]:
    section = README.split("## Development", 1)[1]
    block = re.search(r"```\n(.*?)```", section, re.S)
    assert block is not None
    return [line for line in block.group(1).splitlines() if line.strip()]


def test_the_workflow_runs_every_command_the_readme_lists_for_developers() -> None:
    commands = development_commands()
    assert len(commands) >= 5
    for command in commands:
        # "pytest" in the README is "python -m pytest" in CI, and options may differ
        name = command.removeprefix("python -m ").split(" --")[0].strip()
        assert name in WORKFLOW, command


def plain_scalar_problems(text: str) -> list[str]:
    """Lines GitHub would refuse: YAML cannot have ": " or a tab in an unquoted value. A real
    parser is not available (the standard library has none), so this checks the mistake that
    happened: a step name like `Benchmark (for information: ...)` made the whole file invalid."""
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        if "\t" in line:
            problems.append(f"line {number}: a tab")
        match = re.match(r"^\s*(?:- )?[A-Za-z_-]+: (.+)$", line)
        value = match.group(1) if match else ""
        quoted = value.startswith(('"', "'", "|", ">", "[", "{"))
        if match and not quoted and (": " in value or " #" in value):
            problems.append(f"line {number}: unquoted value with ': ' or ' #': {line.strip()}")
    return problems


def test_the_workflow_is_well_formed_and_runs_the_checks_in_order() -> None:
    assert plain_scalar_problems(WORKFLOW) == []
    assert plain_scalar_problems("- name: Benchmark (for information: the numbers)") != []
    assert plain_scalar_problems("  key:\tvalue") != []
    assert plain_scalar_problems("  name: a # b") != []
    assert plain_scalar_problems('  name: "a: b"') == []
    assert plain_scalar_problems("  run: |") == []
    order = ["ruff check .", "ruff format --check .", "mypy", "python -m pytest", "tools.fuzz"]
    positions = [WORKFLOW.index(step) for step in order]
    assert positions == sorted(positions)


def test_the_workflow_covers_the_python_versions_and_systems_the_project_claims() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    minimum = pyproject["project"]["requires-python"].removeprefix(">=")
    assert f'"{minimum}"' in WORKFLOW  # the oldest version it says it supports
    assert '"3.13"' in WORKFLOW  # the one the author uses
    assert "ubuntu-latest" in WORKFLOW
    assert "windows-latest" in WORKFLOW  # where it is developed


def test_the_workflow_runs_the_tests_that_need_a_real_interface_as_root() -> None:
    assert 'sudo "$(which python)" -m pytest tests/test_live_linux.py' in WORKFLOW
    assert "needs Linux and root" in WORKFLOW  # a skip in that job is a failure
    live = (ROOT / "tests" / "test_live_linux.py").read_text(encoding="utf-8")
    assert '"needs Linux and root"' in live.replace("reason=", "")


def test_the_fuzz_seed_is_the_run_number() -> None:
    assert "--seed ${{ github.run_number }}" in WORKFLOW


def test_the_workflow_can_only_read_the_repository() -> None:
    assert "permissions:\n  contents: read" in WORKFLOW
