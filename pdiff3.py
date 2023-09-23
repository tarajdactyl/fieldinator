#!/usr/bin/env python3

import argparse
import pyshark

class Field():
    def __init__(self, offset, length, values):
        self.offset = offset
        self.length = length
        self.values = values


class pDiff():
    def __init__(self, input_file, display_filter='', packet_offset=0,
            verbose=False, endianness="big"):
        self.input_file = input_file
        self.display_filter = display_filter
        self.packet_offset = packet_offset
        self.verbose = verbose
        self.endianness = endianness
        self.is_pcap = self.magic_is_pcap()

        if self.is_pcap:
            self.packets = pyshark.FileCapture(self.input_file,
                                               use_json=True, include_raw=True,
                                               display_filter=self.display_filter)
        else:
            self.log("Text mode isn't implemented yet")
            return

        self.bytes = {}
        self.words = {}
        self.dwords = {}
        self.fields = []

        self.process_packets()
        self.find_likely_fields()

    def process_packets(self):
        self.bytes = {}
        self.words = {}
        self.dwords = {}
        for pkt in self.packets:
            self.vlog(f"Frame {pkt.number}")
            #self.vlog(f"  {pkt.frame_info}")
            pbytes = bytes.fromhex(pkt.frame_raw.value)
            for i, b in enumerate(pbytes):
                # record bytes
                if i not in self.bytes:
                    self.bytes[i] = {}
                self.bytes[i][b] = self.bytes[i].get(b, 0) + 1

                # record word
                if i + 1 < len(pbytes):
                    if i not in self.words:
                        self.words[i] = {}
                    word = int.from_bytes(pbytes[i:2], self.endianness)
                    self.words[i][word] = self.words[i].get(word, 0) + 1

                # record dword
                if i + 3 < len(pbytes):
                    if i not in self.dwords:
                        self.dwords[i] = {}
                    dword = int.from_bytes(pbytes[i:4], self.endianness)
                    self.dwords[i][dword] = self.dwords[i].get(dword, 0) + 1

    def log(self, *args, **kwargs):
        # todo: proper logging
        print(*args, **kwargs)

    def err(self, *args, **kwargs):
        # todo: make it red or something
        return self.log(*args, **kwargs)

    def vlog(self, *args, **kwargs):
        # todo: proper logging
        if self.verbose:
            print(*args, **kwargs)

    def magic_is_pcap(self):
        """
        Check to see if input file has a PCAP or PCAPNG magic value; otherwise treat it as text.
        """

        """
        PCAP magics:
        a1 b2 c3 d4 if the file was written on a big-endian machine and has
           microsecond-resolution time stamps;
        d4 c3 b2 a1 if the file was written on a little-endian machine and has
           microsecond-resolution time stamps;
        a1 b2 3c 4d if the file was written on a big-endian machine and has
           nanosecond-resolution time stamps;
        4d 3c b2 a1 if the file was written on a little-endian machine and has
           nanosecond-resolution time stamps.

        PCAPNG starts with 0a 0d 0d 0a, and then, at offset 8 in the file:
            1a 2b 3c 4d if the file was written on a big-endian machine;
            4d 3c 2b 1a if the file was written on a little-endian machine;
        """
        pcap_magics = [b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1',
                b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1']
        pcapng_magic1 = b'\x0a\x0d\x0d\x0a'
        pcapng_magic2s = [b'\x1a\x2b\x3c\x4d', b'\x4d\x3c\x2b\x1a']
        with open(self.input_file, 'rb') as infile:
            magic = infile.read(4)
            if magic in pcap_magics:
                self.vlog(f"{self.input_file} is a PCAP file")
                return True
            if magic == pcapng_magic1:
                # skip 4 bytes
                infile.read(4)
                # read 4 bytes starting at offset 8
                magic = infile.read(4)
                if magic in pcapng_magic2s:
                    self.vlog(f"{self.input_file} is a PCAPNG file")
                    return True
        self.vlog(f"{self.input_file} is not a PCAP[NG] file; treating it as text")
        return False

    def show_heatmap(self):
        pass

    def show(self, freqarray, label, width):
        for i in sorted(freqarray.keys()):
            print(f"{label}@{i:#x}:")
            for val, freq in sorted(freqarray[i].items(), key=lambda x: x[1], reverse=True):
                # todo: add a percent or something other than just count
                print(f"  {val:0{width}x} ({freq})")

    def show_bytes(self):
        return self.show(self.bytes, "Byte", 2)

    def show_words(self):
        return self.show(self.words, "Word", 4)

    def show_dwords(self):
        return self.show(self.dwords, "DWord", 8)

    def find_likely_fields(self):
        """
        Attempt to guess likely field sizes based on frequency analysis of bytes, words, and dwords.
        Note that this builds out fields greedily, and may not be optimal
        """
        # for each offset in the packet, look at the number of values seen with bytes, words, dwords;
        # prefer the largest-size field with the smallest number of possible options.

        self.fields = []
        offset = 0
        while offset < len(self.bytes.keys()) - 4:
            b_count = max(len(self.bytes[o].keys()) for o in range(offset,offset+4))
            w_count = max(len(self.words[o].keys()) for o in range(offset, offset+3))
            d_count = len(self.dwords[offset].keys())

            if d_count >= w_count >= b_count:
                width = 4
                values = self.dwords[offset]
            elif w_count >= b_count:
                width = 2
                values = self.words[offset]
            else:
                width = 1
                values = self.bytes[offset]

            self.fields.append(Field(offset, width, values))
            offset += width

    def show_likely_fields(self):
        for field in self.fields:
            typestr="Unknown"
            if field.length == 1:
                typestr = "Byte"
            elif field.length == 2:
                typestr = "Word"
            elif field.length == 4:
                typestr = "DWord"

            print(f'{field.offset:#02x}: likely {typestr}')
            for val, freq in field.values.items():
                print(f"  {val:#0{field.length * 2}x} ({freq})")


    def show_strings(self):
        self.log('not implemented')
        pass


def main():
    parser = argparse.ArgumentParser("pDiff3")
    parser.add_argument('input', help='Input File to Analyze')
    parser.add_argument('--filter', '-f', default="", help='Display Filter to use (PCAPs only)')
    parser.add_argument('--packet-offset', '-o', type=lambda x: int(x,0), default=0,
                        help='Offset in packet to diff (PCAPs only)')
    parser.add_argument('--endian', '-e', choices=['little', 'big'],
            help="endianness for multi-byte integers", default='big')
    parser.add_argument('--verbose', '-v', action="store_true", help='verbose output')
    parser.add_argument('--fields', '-F', action="store_true",
            help='List likely fields and their common values based on frequency analysis')
    parser.add_argument('--bytes', '-b', action="store_true", help='List common bytes per offset')
    parser.add_argument('--words', '-w', action="store_true",
                        help='List common words (uint16) per offset')
    parser.add_argument('--dwords', '-d', action="store_true",
                        help='List common dwords (uint32) per offset')
    parser.add_argument('--strings', '-s', action="store_true", help='Show string stats')
    # TODO:
    # - specify dissection layer (-l)
    args = parser.parse_args()
    pd = pDiff(args.input, args.filter, args.packet_offset, args.verbose, args.endian)
    #pd.show_heatmap()
    if args.fields:
        pd.show_likely_fields()
    if args.bytes:
        pd.show_bytes()
    if args.words:
        pd.show_words()
    if args.dwords:
        pd.show_dwords()
    if args.strings:
        pd.show_strings()

if __name__ == '__main__':
    main()
