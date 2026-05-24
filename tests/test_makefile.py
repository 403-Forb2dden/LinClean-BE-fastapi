from pathlib import Path


def test_run_target_reloads_app_only() -> None:
    makefile = Path("Makefile").read_text()
    run_block = makefile.split("run:  ## Run the API locally with hot reload", 1)[1].split(
        "\n\n", 1
    )[0]

    assert "--reload-dir app" in run_block
    assert "--reload-exclude .venv" in run_block
