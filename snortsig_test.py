import snortsig
import requests
import pytest

#TODO: add search tests
#TODO: add tests with known difficult signatures

def test_parse_content_order():
    #TODO: implement content order tests
    pass

def test_parse_VRT_community():
    response = requests.get("https://s3.amazonaws.com/snort-org/www/rules/community/community-rules.tar.gz")
    results = tarfile.open(mode='r:gz', fileobj=StringIO(response.content))
    sig_fobj=results.extractfile('community-rules/community.rules')
    ss = snortsig.SnortSig()
    ss.readString(sig_fobj.read())
    assert len(ss.unparsed()) == 1
    assert len(ss.getall()) == len(ss.search("1",attribute="disabled")) + len(ss.search("0",attribute="disabled"))

def test_parse_ET_Open():
    #TODO: implement test with the ET Open ruleset
    pass

if __name__ == '__main__':
    pytest.main()