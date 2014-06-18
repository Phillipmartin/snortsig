import snortsig
import requests
import pytest
import tarfile
import StringIO

#TODO: add search tests
#TODO: add tests with known difficult signatures

def test_parse_content_order():
    #TODO: implement content order tests
    pass

def test_single_sig():
    sig='alert tcp [$HOME_NET,10.1.1.1,10.1.1.0/24] any -> $EXTERNAL_NET [$HTTP_PORTS,443] (msg:"MALWARE-CNC Sality logo.gif URLs"; flow:to_server,established; content:"/logo.gif?"; fast_pattern:only; http_uri; pcre:"/\x2Flogo\.gif\x3F[0-9a-f]{5,7}=\d{5,7}/Ui"; metadata:policy balanced-ips drop, policy security-ips drop, ruleset community, service http; reference:url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?name=Virus%3aWin32%2fSality.AT; classtype:trojan-activity; sid:24255; rev:3;)'
    ss=snortsig.SnortSig()
    ss.fromstring(sig)
    assert len(ss.sigs) == 1
    sig_obj=ss.search("",exact=False)
    assert len(sig_obj) == 1
    assert len(ss.search("asdfsadf")) == 0
    assert sig_obj[0]["direction"][0] == '->'
    assert sig_obj[0]["action"][0] == 'alert'
    assert sig_obj[0]["protocol"][0] == 'tcp'
    assert len(sig_obj[0]["src"]) == 3
    assert len(sig_obj[0]["dst"]) == 1
    assert len(sig_obj[0]["dst_port"]) == 2
    assert sig_obj[0]["dst_port"][1] == '443'

def test_parse_VRT_community():
    response = requests.get("https://s3.amazonaws.com/snort-org/www/rules/community/community-rules.tar.gz")
    results = tarfile.open(mode='r:gz', fileobj=StringIO.StringIO(response.content))
    sig_fobj=results.extractfile('community-rules/community.rules')
    ss = snortsig.SnortSig()
    ss.fromstring(sig_fobj.read())
    assert len(ss.unparsed()) == 1
    assert len(ss.getall()) == len(ss.search("1",attribute="disabled")) + len(ss.search("0",attribute="disabled"))

def test_parse_ET_Open():
    response = requests.get('https://rules.emergingthreats.net/open-nogpl/snort-2.9.0/emerging-all.rules')
    ss = snortsig.SnortSig()
    ss.fromstring(response.text)
    assert len(ss.getall()) == len(ss.search("1",attribute="disabled")) + len(ss.search("0",attribute="disabled"))

if __name__ == '__main__':
    pytest.main()