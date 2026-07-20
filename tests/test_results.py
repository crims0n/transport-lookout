from pathlib import Path

from scanpod_enterprise.models import HostObservation, ServiceObservation
from scanpod_enterprise.results import normalize_nmap_xml


def test_nmap_xml_normalizes_hosts_and_services(tmp_path: Path, clean_database):
    xml = tmp_path / "result.xml"
    xml.write_text("""<?xml version='1.0'?>
    <nmaprun><host><status state='up'/><address addr='10.1.2.3' addrtype='ipv4'/>
    <hostnames><hostname name='server.example'/></hostnames><ports>
    <port protocol='tcp' portid='443'><state state='open'/><service name='https' product='nginx' version='1.25'/></port>
    </ports></host></nmaprun>""")
    from scanpod_enterprise.db import SessionLocal
    with SessionLocal() as session:
        assert normalize_nmap_xml(session, xml, "run-1", "shard-1") == 1
        session.commit()
        host = session.query(HostObservation).one()
        service = session.query(ServiceObservation).one()

    assert (host.address, host.hostname, host.state) == ("10.1.2.3", "server.example", "up")
    assert (service.port, service.protocol, service.service, service.product) == (443, "tcp", "https", "nginx")
