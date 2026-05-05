from phishing.url_defanger import defang, refang


def test_defang_url():
    assert defang("https://example.com/login") == "hxxps://example[.]com/login"


def test_refang_url():
    assert refang("hxxps://example[.]com/login") == "https://example.com/login"
