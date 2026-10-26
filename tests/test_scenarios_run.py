# SPDX-License-Identifier: Apache-2.0
"""Every test that defines an async scenario runs it.

A test that defines ``async def scenario()`` and forgets ``run(scenario())`` passes without
checking anything, and the coverage threshold does not notice. This looks, in every test file,
for a test function that defines an inner ``async def`` and never uses its name.
"""

import ast
from pathlib import Path

import pytest

TESTS = Path(__file__).parent


class Unused(ast.NodeVisitor):
    """The inner ``async def`` of one function that its function never mentions."""

    def __init__(self) -> None:
        self.defined: dict[str, int] = {}
        self.used: set[str] = set()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.defined.setdefault(node.name, node.lineno)
        for decorator in node.decorator_list:
            self.visit(decorator)
        # A name used inside the function itself, as a recursion would, is not a use of it.
        inner = Unused()
        for statement in node.body:
            inner.visit(statement)
        self.used |= inner.used - {node.name}
        for name, line in inner.defined.items():
            self.defined.setdefault(name, line)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class's body for what it uses; its methods are called as methods."""
        for statement in node.body:
            if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
                for decorator in statement.decorator_list:
                    self.visit(decorator)
                for inner in statement.body:
                    self.visit(inner)
            else:
                self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for statement in node.body:
            self.visit(statement)

    def visit_Name(self, node: ast.Name) -> None:
        self.used.add(node.id)


def unrun_scenarios(source: str) -> list[tuple[str, str, int]]:
    """Return ``(test, inner function, line)`` for each inner ``async def`` a test never uses."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith(
            "test_"
        ):
            visitor = Unused()
            for statement in node.body:
                visitor.visit(statement)
            found += [
                (node.name, name, line)
                for name, line in visitor.defined.items()
                if name not in visitor.used
            ]
    return sorted(found, key=lambda entry: entry[2])


def test_no_test_defines_a_scenario_it_does_not_run() -> None:
    problems = [
        f"{path.name}:{line}: {test} defines {inner}() and never uses it"
        for path in sorted(TESTS.glob("*.py"))
        for test, inner, line in unrun_scenarios(path.read_text(encoding="utf-8"))
    ]
    assert not problems, "\n".join(problems)


# -- the guard itself ----------------------------------------------------------------------

GOOD = """
def test_runs_it():
    async def scenario():
        await helper()
    run(scenario())

def test_passes_it_on():
    async def scenario():
        pass
    asyncio.run(asyncio.wait_for(scenario(), 5))

def test_hands_over_a_callback():
    async def connect(address, port):
        pass
    options = {"connector": connect}

def test_uses_one_inside_another():
    async def inner():
        pass
    async def scenario():
        await inner()
    run(scenario())

def test_with_a_class_whose_method_is_async():
    class Window:
        async def wait(self):
            pass
    async def scenario():
        await Window().wait()
    run(scenario())

def helper_that_is_not_a_test():
    async def scenario():
        pass
"""

BAD = """
def test_forgot_to_run_it():
    async def scenario():
        assert False
    print("nothing runs")

def test_recursion_is_no_use():
    async def scenario():
        await scenario()

def test_only_one_of_two():
    async def used():
        pass
    async def forgotten():
        pass
    run(used())

class TestInAClass:
    def test_method(self):
        async def scenario():
            pass
"""


def test_the_guard_passes_scenarios_that_are_run_or_handed_on() -> None:
    assert unrun_scenarios(GOOD) == []


def test_the_guard_names_each_test_and_scenario_it_never_runs() -> None:
    assert [(test, inner) for test, inner, _ in unrun_scenarios(BAD)] == [
        ("test_forgot_to_run_it", "scenario"),
        ("test_recursion_is_no_use", "scenario"),
        ("test_only_one_of_two", "forgotten"),
        ("test_method", "scenario"),
    ]


@pytest.mark.parametrize("name", ["test_daemon.py", "test_bridge.py", "test_mcp_server.py"])
def test_the_guard_fails_on_a_real_test_file_with_a_run_line_removed(name: str) -> None:
    """The tree passes, and the same file with one ``run(scenario())`` taken out does not."""
    source = (TESTS / name).read_text(encoding="utf-8")
    assert unrun_scenarios(source) == []
    broken = source.replace("    run(scenario())\n", "    pass\n", 1)
    assert broken != source
    found = unrun_scenarios(broken)
    assert len(found) == 1
    assert found[0][1] == "scenario"
