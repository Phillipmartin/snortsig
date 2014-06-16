import snortsig
import pytest

def test_match_msg():
    msg = 'msg:"test";'
    result = snortsig.SnortSig._quoted_element.parseString(msg)
    assert result[0] == "msg"
    assert result[1] == '"test"'

def test_match_reference():
    reference = 'reference:bugtraq,1387;'
    result = snortsig.SnortSig._reference_element.parseString(reference)
    assert result[0] == "reference"
    assert result[1] == "bugtraq"
    assert result[1] == "1387"

def test_match_gid():
    gid = 'gid:1000001;'
    result = snortsig.SnortSig._number_element.parseString(gid)
    assert result[0] == "gid"
    assert result[1] == "1000001"

def test_match_sid():
    sid = 'sid:1000983;'
    result = snortsig.SnortSig._number_element.parseString(sid)
    assert result[0] == "sid"
    assert result[1] == "1000983"

def test_match_rev():
    rev = 'rev:1;'
    result = snortsig.SnortSig._number_element.parseString(rev)
    assert result[0] == "rev"
    assert result[1] == "1"

def test_match_classtype():
    classtype = 'classtype:attempted-recon;'
    result = snortsig.SnortSig._quoted_element.parseString(classtype)
    assert result[0] == "classtype"
    assert result[1] == "attempted-recon"

def test_match_priority():
    priority = 'priority:10;'
    result = snortsig.SnortSig._number_element.parseString(priority)
    assert result[0] == "priority"
    assert result[1] == "10"

def test_match_metadata():
    metadata = 'metadata:key1 value1, key2 value2;'
    result = snortsig.SnortSig._metadata_element.parseString(metadata)
    assert result[1][1] == "value1"
    assert result[2][1] == "value2"


def test_match_content():
    content = 'content:!"|5c 00|P|00|I|00|P|00|E|00 5c|";'
    result = snortsig.SnortSig._content_element.parseString(metadata)
    assert result[1][1] == "value1"
    assert result[2][1] == "value2"
if __name__ == '__main__':
    pytest.main()