from pathlib import Path


def test_run_target_does_not_use_reload_watcher() -> None:
    makefile = Path("Makefile").read_text()
    run_block = makefile.split("run:  ## Run the API locally", 1)[1].split("\n\n", 1)[0]

    assert "--reload" not in run_block


def test_dev_target_reloads_app_only() -> None:
    makefile = Path("Makefile").read_text()
    dev_block = makefile.split("dev:  ## Run the API locally with hot reload", 1)[1].split(
        "\n\n", 1
    )[0]

    assert "--reload-dir app" in dev_block
    assert "--reload-exclude .venv" in dev_block
