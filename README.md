# snortsig
[![Build Status](https://travis-ci.org/Phillipmartin/snortsig.svg?branch=master)](https://travis-ci.org/Phillipmartin/snortsig)
A read-only (for now) interface to snort signatures using pyparsing on the back end.  You can parse signatures from multiple files, or just via a string.  Once parsed, you can use the search() method to retrieve signatures with specific attributes.

## Known Bugs
   * snortsig currently doesn't deal well with escaped semi-colons.
   * snortsig currently doesn't deal well with double quotes inside quoted fields.
   * snortsig can't write signatures back out to strings or files.

## Example

Get a count of enabled and disabled signatures from a downloaded copy of the VRT community ruleset:

    In [1]: ss=snortsig.SnortSig()

    In [2]: ss.fromFile("community.rules")

    In [3]: len(ss.search("0",attribute='disabled'))
    Out[3]: 495

    In [4]: len(ss.search("1",attribute='disabled'))
    Out[4]: 2507

    In [5]: len(ss.search("", exact=False))
    Out[5]: 3002

Which signatures were unparsable?

    In [11]: ss.unparsed()
    Out[11]:
    ['# alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SERVER-IIS Al
    ternate Data streams ASP file access attempt"; flow:to_server,established; conte
    nt:".asp|3A 3A 24|DATA"; nocase; http_uri; metadata:ruleset community, service h
    ttp; reference:bugtraq,149; reference:cve,1999-0278; reference:nessus,10362; ref
    erence:url,support.microsoft.com/default.aspx?scid=kb\\;EN-US\\;q188806; classty
    pe:web-application-attack; sid:975; rev:26;)',
     '']

Of all of the enabled signatures, which classtypes are the most common?

    In [1]: enabled = ss.search("0",attribute='disabled')

    In [2]: collections.Counter([e['options']['classtype'][0] for e in enabled])
    Out[2]: Counter({'trojan-activity': 451, 'attempted-recon': 27, 'misc-activity'
    : 10, 'attempted-admin': 4, 'bad-unknown': 1, 'network-scan': 1, 'unsuccessful-u
    ser': 1})

Of all of the disabled signatures, which classtypes are the most common?

    In [1]: disabled = ss.search("1",attribute='disabled')

    In [2]: collections.Counter([e['options']['classtype'][0] for e in disabled])
    Out[2]: Counter({'web-application-activity': 479, 'attempted-user': 343, 'attem
    pted-recon': 332, 'web-application-attack': 267, 'attempted-admin': 220, 'misc-a
    ctivity': 164, 'trojan-activity': 155, 'protocol-command-decode': 112, 'misc-att
    ack': 101, 'rpc-portmap-decode': 83, 'attempted-dos': 60, 'policy-violation': 52
    , 'bad-unknown': 44, 'shellcode-detect': 26, 'suspicious-login': 16, 'successful
    -admin': 9, 'unsuccessful-user': 9, 'network-scan': 6, 'suspicious-filename-dete
    ct': 6, 'default-login-attempt': 6, 'system-call-detect': 5, 'successful-recon-l
    imited': 4, 'unknown': 2, 'denial-of-service': 2, 'string-detect': 2, 'successfu
    l-user': 1, 'non-standard-protocol': 1})

How many signatures use the 'itype' attribute?

    In [1]: len(ss.search("",attribute='itype',exact=False))
    Out[1]: 123

## How To Use
### Install
    pip install snortsig

### Import
    import snortsig

### Instantiate
    ss=snortsig.SnortSig()
    ss.fromFile("community.rules")
    ss.fromFile("emerging-all.rules")
    ss.fromString('alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE-CNC Sality logo.gif URLs"; flow:to_server,established; content:"/logo.gif?"; fast_pattern:only; http_uri; pcre:"/\x2Flogo\.gif\x3F[0-9a-f]{5,7}=\d{5,7}/Ui"; metadata:policy balanced-ips drop, policy security-ips drop, ruleset community, service http; reference:url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?name=Virus%3aWin32%2fSality.AT; classtype:trojan-activity; sid:24255; rev:3;)')

### fromString(string)

Parse the provided string and extract the snort signatures

### fromFile(file)

Read the supplied file and feed it to fromString()

### getall()

Return all parsed signatures as a list of signature dicts.

### search(term, attribute=None, exact=False)

Search through all imported signatures and return those that match the query as a list of signature dicts.
   * term is a string to match.
   * attribute is the name of an option or header to search.  If attribute is None, search all options and headers.
   * exact controls the match type, exact or substring.

For example, return all signatures with the pcre option:

    search("",attribute="pcre",exact=False)

### unparsed()

Return all signatures that failed parsing as a list of strings

### Work with individual signatures

Rather than create an object to encapsulate a single snort signature, we just stuff the signature into a dict.  The overall concept should be fairly easy to grok if you understand snort signature syntax, but there are a couple of non-obvious bits:

   * the 'disabled' key indicates the presence (1) or absence (0) of a hash mark before the signature at import time.
   * the options key holds all of the rule options.
   * for payload detection options that take modifiers, the modifiers are grouped with the option to which they apply
   * order is preserved
   * all of the values are lists.  Where options have multiple values (or there are multiple instances of an option), the lists may be nested.  Where options have simple string values, the top level list contains a strings.  This is done to maintain consistent semantics when accessing data.


Example signature dict:

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