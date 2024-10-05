from pytest_archon import archrule


def test_does_not_import_passlib() -> None:
    (
        archrule("forbid-passlib-import")
        .match("libpass*")
        .should_not_import("passlib*")
        .check("libpass")
    )
