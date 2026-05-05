from iocs.ioc_deduplicator import classer_ioc, refang


def test_refang_domain():
    assert refang("evil[.]com") == "evil.com"


def test_classer_ip():
    assert classer_ioc("8.8.8.8") == "ips"


def test_classer_hash():
    assert classer_ioc("a" * 64) == "hashes"
