from __future__ import annotations

import subprocess
import sys


def _run_python(code: str) -> str:
    result = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def test_select_ai_provider_always_uses_openai_even_when_disabled():
    output = _run_python(
        "import sys\n"
        "import app.main as main\n"
        "main.settings.ai_provider = 'null'\n"
        "main.settings.openai_api_key = None\n"
        "provider = main._select_ai_provider()\n"
        "print(type(provider).__name__, 'openai' in sys.modules)\n"
    )

    assert output == "OpenAIProvider False"


def test_select_ai_provider_with_key_defers_openai_sdk_import():
    output = _run_python(
        "import sys\n"
        "import app.main as main\n"
        "main.settings.ai_provider = 'auto'\n"
        "main.settings.openai_api_key = 'test-key'\n"
        "provider = main._select_ai_provider()\n"
        "print(type(provider).__name__, 'openai' in sys.modules)\n"
    )

    assert output == "OpenAIProvider False"
