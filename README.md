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

