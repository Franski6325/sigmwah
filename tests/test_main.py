from sigmwah.cli import app


def test_import_main() -> None:
    import sigmwah.__main__ as main

    assert main.app is app
