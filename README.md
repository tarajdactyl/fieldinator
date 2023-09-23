PDiff3
======

A spiritual descendent of @netspooky's pdiff2; there were features I wanted
to add to pdiff2, but I also wanted to rework some things and had considered
completely changing the way some things worked...

I also dropped some features that I didn't care about right now. Basically
pdiff2 was _almost_ the tool I wanted, but not quite a proper subset of the
tool I wanted, so I started from scratch with an idea. So maybe this is less
"child of pdiff" and more "weird niece of pdiff" or "gay cousin of pdiff".
Whatever.

Anyway, here we are. With thanks and apologies to @netspooky <3


Setup
-----

Prerequesites: python3, wireshark, tshark are installed

Create venv and install python prereqs:
```
$ python3 -m venv venv
$ source venv/bin/activate
$ pip3 install -r requirements.txt
```

Usage
-----

### tl;dr:
```
./pdiff3 INPUT_FILE
```

By default, it will analyze the packets in a provided PCAP and attempt to find
"fields" by looking at commonly-occurring strings of bytes. If any bytes or
words within a given 4-byte sequence changes less frequently than the whole
4-byte sequence, then it will consider splitting into smaller fields. It will
print a heatmap of the fields, colored by how many values were observed for
that field in the given pcap.

### Full Usage:
```
usage: pDiff3 [-h] [--filter FILTER] [--packet-offset PACKET_OFFSET]
              [--endian {little,big}] [--verbose] [--fields] [--bytes]
              [--words] [--dwords] [--strings] [--protocol PROTOCOL]
              [--protocol-field PROTOCOL_FIELD]
              input

positional arguments:
  input                 Input File to Analyze

options:
  -h, --help            show this help message and exit
  --filter FILTER, -f FILTER
                        Display Filter to use (PCAPs only)
  --packet-offset PACKET_OFFSET, -o PACKET_OFFSET
                        Offset in packet to diff (PCAPs only)
  --endian {little,big}, -e {little,big}
                        endianness for multi-byte integers
  --verbose, -v         verbose output
  --fields, -F          List likely fields and their common values based on
                        frequency analysis
  --bytes, -b           List common bytes per offset
  --words, -w           List common words (uint16) per offset
  --dwords, -d          List common dwords (uint32) per offset
  --strings, -s         Show string stats
  --protocol PROTOCOL, -p PROTOCOL
                        protocol layer to start at instead of whole frame
  --protocol-field PROTOCOL_FIELD
                        Name of field within protocol to use for analysis
                        instead of the whole frame
```
