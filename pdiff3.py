#!/usr/bin/env python3

import argparse
import pyshark

class pDiff():

    def __init__(self, input_file, display_filter='', packet_offset=0, verbose=False):
        self.input_file = input_file
        self.display_filter = display_filter
        self.packet_offset = packet_offset
        self.verbose = verbose
        self.is_pcap = self.magic_is_pcap()

    def log(self, *args, **kwargs):
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
                self.log(f"{self.input_file} is a PCAP file")
                return True
            if magic == pcapng_magic1:
                # skip 4 bytes
                infile.read(4)
                # read 4 bytes starting at offset 8
                magic = infile.read(4)
                if magic in pcapng_magic2s:
                    self.log(f"{self.input_file} is a PCAPNG file")
                    return True
        self.log(f"{self.input_file} is not a PCAP[NG] file; treating it as text")
        return False

    def show_heatmap(self):
        self.log('not implemented')
        pass

    def show_bytes(self):
        self.log('not implemented')
        pass

    def show_words(self):
        self.log('not implemented')
        pass

    def show_dwords(self):
        self.log('not implemented')
        pass

    def show_strings(self):
        self.log('not implemented')
        pass


def main():
    parser = argparse.ArgumentParser("pDiff3")
    parser.add_argument('input', help='Input File to Analyze')
    parser.add_argument('--filter', '-f', default="", help='Display Filter to use (PCAPs only)')
    parser.add_argument('--packet-offset', '-o', type=lambda x: int(x,0), default=0,
                        help='Offset in packet to diff (PCAPs only)')
    parser.add_argument('--verbose', '-v', action="store_true", help='verbose output')
    parser.add_argument('--bytes', '-b', action="store_true", help='List common bytes per offset')
    parser.add_argument('--words', '-w', action="store_true",
                        help='List common words (uint16) per offset')
    parser.add_argument('--dwords', '-d', action="store_true",
                        help='List common dwords (uint32) per offset')
    parser.add_argument('--strings', '-s', action="store_true", help='Show string stats')
    # TODO:
    # - specify dissection layer (-l)
    args = parser.parse_args()
    pd = pDiff(args.input, args.filter, args.packet_offset, args.verbose)
    pd.show_heatmap()
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
