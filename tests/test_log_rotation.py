"""Exercise real redirected descriptors, backup retention, restart and failure."""
import argparse
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--client", required=True)
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix="edr-log-rotation-") as temp:
    root = Path(temp)
    subprocess.run([args.client, temp, "rotate"], check=True)
    assert (root / "agent.log").read_text() == "after-rotation\n"
    assert (root / "agent.log.1").read_text().startswith("cycle-2\n")
    assert (root / "agent.log.2").read_text().startswith("cycle-1\n")
    assert not (root / "agent.log.3").exists()
    subprocess.run([args.client, temp, "restart"], check=True)
    assert (root / "agent.log").read_text() == "after-rotation\nafter-restart\nafter-failed-config\n"
    subprocess.run([args.client, temp, "reduce-retention"], check=True)
    assert (root / "agent.log.1").exists() and not (root / "agent.log.2").exists()
with tempfile.TemporaryDirectory(prefix="edr-log-rotation-failure-") as temp:
    root = Path(temp)
    # A nonempty backup directory rejects removal/rename on every platform.
    (root / "agent.log.2").mkdir()
    (root / "agent.log.2" / "preserved").write_text("fixture")
    subprocess.run([args.client, temp, "rename-failure"], check=True)
    data = (root / "agent.log").read_text()
    assert "rotation failed" in data and data.endswith("after-failed-rotation\n")

with tempfile.TemporaryDirectory(prefix="edr-log-zero-backup-") as temp:
    root = Path(temp)
    subprocess.run([args.client, temp, "zero-backups"], check=True)
    assert (root / "agent.log").read_text() == "after-truncation\n"
    assert not (root / "agent.log.1").exists()

with tempfile.TemporaryDirectory(prefix="edr-log-rebind-retention-") as temp:
    root = Path(temp)
    subprocess.run([args.client, temp, "replacement-failure-retention"], check=True)
    assert not (root / "agent.log").exists()
    assert (root / "agent.log.1").read_text().endswith("after-pending-retention-failure\n")
