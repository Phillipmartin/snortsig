# snortsig
A read-only (for now) interface to snort signatures.  You can parse signatures from multiple files, or just via a string.  Once parsed, you can use the search() method to retrieve signatures with specific attributes.

## Prerequisites

## Example

## How To Use
### Install
    pip install snortsig

### Import
    import snortsig

### Instantiate
    ss=snortsig.SnortSig()
    ss.fromFile("community.rules")
    ss.fromFile("emerging-all.rules")

### search()

    ss.search()

### unparsed()

    ss.unparsed()

### Work with individual signatures

    {'action': ['alert'],
      'direction': ['->'],
      'disabled': ['1'],
      'dst': ['$SMTP_SERVERS'],
      'dst_port': ['25'],
      'options': {'classtype': ['attempted-admin'],
       'content': ['|EB|E|EB| [|FC|3|C9 B1 82 8B F3 80|+',
        ['fast_pattern', 'only']],
       'flow': ['to_server', 'established'],
       'metadata': [['ruleset', 'community'], ['service', 'smtp']],
       'msg': ['SERVER-MAIL x86 windows MailMax overflow'],
       'reference': [['bugtraq', '2312'], ['cve', '1999-0404']],
       'rev': ['13'],
       'sid': ['310']},
      'protocol': ['tcp'],
      'src': ['$EXTERNAL_NET'],
      'src_port': ['any']}