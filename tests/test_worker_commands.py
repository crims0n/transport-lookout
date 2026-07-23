from pathlib import Path

from scanpod_enterprise.models import ScanProfile
from scanpod_enterprise.worker import nmap_confirmation_command


def test_masscan_confirmation_forces_nmap_to_skip_host_discovery():
    profile = ScanProfile(name="perimeter", version=1, ports="443", arguments="-sV -n", max_rate=500)

    command = nmap_confirmation_command(profile, Path("/tmp/result.xml"), Path("/tmp/targets.txt"))

    assert command == [
        "nmap",
        "-Pn",
        "-oX",
        "/tmp/result.xml",
        "-iL",
        "/tmp/targets.txt",
        "-p",
        "443",
        "-sV",
        "-n",
        "--max-rate",
        "500",
    ]
