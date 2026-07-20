"""Nmap XML normalization and raw-artifact storage."""
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

from sqlalchemy.orm import Session

from .config import settings
from .models import HostObservation, ServiceObservation


def store_artifact(source: Path, run_id: str, shard_id: str) -> str:
    """Persist a raw XML artifact beneath the configured storage root.

    The path is an internal key, deliberately not a client-provided filename.
    A future S3-compatible implementation can preserve this interface.
    """
    relative = Path(run_id) / f"{shard_id}.xml"
    destination = Path(settings.artifact_root) / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), destination)
    return str(relative)


def normalize_nmap_xml(session: Session, xml_path: Path, run_id: str, shard_id: str) -> int:
    root = ET.parse(xml_path).getroot()
    count = 0
    for host_node in root.findall("host"):
        address_node = host_node.find("address[@addrtype='ipv4']")
        if address_node is None:
            address_node = host_node.find("address")
        status_node = host_node.find("status")
        if address_node is None or status_node is None:
            continue
        hostname_node = host_node.find("hostnames/hostname")
        host = HostObservation(
            run_id=run_id,
            shard_id=shard_id,
            address=address_node.attrib["addr"],
            state=status_node.attrib.get("state", "unknown"),
            hostname=hostname_node.attrib.get("name") if hostname_node is not None else None,
        )
        session.add(host)
        session.flush()
        count += 1
        for port_node in host_node.findall("ports/port"):
            state_node = port_node.find("state")
            if state_node is None:
                continue
            service_node = port_node.find("service")
            session.add(ServiceObservation(
                host_observation_id=host.id,
                protocol=port_node.attrib.get("protocol", "unknown"),
                port=int(port_node.attrib["portid"]),
                state=state_node.attrib.get("state", "unknown"),
                service=service_node.attrib.get("name") if service_node is not None else None,
                product=service_node.attrib.get("product") if service_node is not None else None,
                version=service_node.attrib.get("version") if service_node is not None else None,
            ))
    return count
