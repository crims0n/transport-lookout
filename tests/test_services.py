import pytest
from fastapi import HTTPException

from scanpod_enterprise.services import parse_approved_cidr, shard_cidr


def test_a_16_shards_to_256_24s():
    assert len(shard_cidr("10.0.0.0/16")) == 256
    assert shard_cidr("10.0.4.0/24") == ["10.0.4.0/24"]


@pytest.mark.parametrize("value", ["10.0.1.1/16", "10.0.0.0/15", "2001:db8::/32"])
def test_rejects_noncanonical_or_overbroad_networks(value):
    with pytest.raises(HTTPException):
        parse_approved_cidr(value)
