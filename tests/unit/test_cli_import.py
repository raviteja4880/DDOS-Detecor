import subprocess
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_import_ddos_detector():
    result = subprocess.run(
        [sys.executable, "-c", "import ddos_detector; print('IMPORT OK')"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert result.returncode == 0
    assert "IMPORT OK" in result.stdout


def test_cli_help_works():
    result = subprocess.run(
        [sys.executable, "-m", "ddos_detector", "--help"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert result.returncode == 0
    assert "Passive network monitoring foundation" in result.stdout


def test_monitor_help_works():
    result = subprocess.run(
        [sys.executable, "-m", "ddos_detector", "monitor", "--help"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert result.returncode == 0
    assert "usage: ddos_detector monitor" in result.stdout
