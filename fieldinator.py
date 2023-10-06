#!/usr/bin/env python3

import argparse
import math
import pyshark
import colorsys
import sys

from blessed import Terminal

def heatMapColor(value):
    """
    get RGB color for heatmap given a float value between 0 and 1
    """
    h = ((1.0 - value) * 240) / 360
    return [math.floor(x*255+.5) for x in colorsys.hls_to_rgb(h, .5, 1)]


class Field():
    def __init__(self, offset, length, freqs_dict, endianness='big'):
        self.offset = offset
        self.length = length
        # dictionary of values and frequencey
        self.freqs = freqs_dict
        self.endianness = endianness
        self.fixed_value = None
        if len(self.freqs.keys()) == 1:
            self.fixed_value = list(self.freqs.keys())[0]

    def __str__(self, skip=0, trunc=None):
        bytes_to_print = []

        if trunc and trunc >= self.length:
            trunc = None

        if self.fixed_value is not None:
            bs = self.fixed_value.to_bytes(self.length, byteorder=self.endianness)[skip:trunc]
            bytes_to_print.extend(f'{b:02x}' for b in bs)
        else:
            l = self.length
            if trunc:
                l = min(self.length, trunc)
            bytes_to_print.extend(['xx'] * (l-skip))


        return ' '.join(bytes_to_print)

class Fieldinator():
    def __init__(self, input_file, display_filter='', packet_offset=0,
            verbose=False, endianness="big", protocol=None, protocol_field=None):
        self.input_file = input_file
        self.display_filter = display_filter
        self.packet_offset = packet_offset
        self.verbose = verbose
        self.endianness = endianness
        self.is_pcap = self.magic_is_pcap()
        if protocol:
            self.protocol = protocol
        else:
            self.protocol = "frame"

        self.protocol_field = None
        if protocol_field:
            self.protocol_field = protocol_field

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
        self.fields = {}
        self.fieldoffset_by_byteoffset = {}

        # initialize TUI
        self.term = Terminal()

        # process packets and find fields
        ret = self.process_packets()
        if ret != -1:
            self.find_likely_fields()


    def process_packets(self):
        self.bytes = {}
        self.words = {}
        self.dwords = {}
        for pkt in self.packets:
            self.vlog(f"Frame {pkt.number}")
            #self.vlog(f"  {pkt.frame_info}")
            #pbytes = bytes.fromhex(pkt.frame_raw.value)[self.packet_offset:]

            layername = self.protocol
            if not self.protocol_field:
                layername = f'{self.protocol}_raw'

            if not layername in (l.layer_name for l in pkt.layers):
                self.err(f"Layer {layername} does not exist in this packet!\n"
                        "Try setting a filter to include only packets with "
                        "the protocol you're interested in!")
                return -1

            layer = pkt[layername]

            pbytes = b''
            if self.protocol_field:
                fieldname = f"{self.protocol_field}_raw"
                if not fieldname in layer.field_names:
                    self.err(f"Layer {layername} does not exist in this packet!\n"
                            "Try setting a filter to include only packets with "
                            "the field you're interested in!")
                    return -1

                rawfield = getattr(layer, fieldname)
                pbytes = bytes.fromhex(rawfield[0])
            else:
                pbytes = bytes.fromhex(layer.value)[self.packet_offset:]

            self.vlog(pbytes)
            for i, b in enumerate(pbytes):
                # TODO: check values against the length of the packet/length remaining
                # both inclusive and exclusive of the field; add these to "potential lengths"
                # record bytes
                # TODO: track strings
                if i not in self.bytes:
                    self.bytes[i] = {}
                self.bytes[i][b] = self.bytes[i].get(b, 0) + 1

                # record word
                if i + 1 < len(pbytes):
                    if i not in self.words:
                        self.words[i] = {}
                    word = int.from_bytes(pbytes[i:i+2], self.endianness)
                    self.words[i][word] = self.words[i].get(word, 0) + 1

                # record dword
                if i + 3 < len(pbytes):
                    if i not in self.dwords:
                        self.dwords[i] = {}
                    dword = int.from_bytes(pbytes[i:i+4], self.endianness)
                    self.dwords[i][dword] = self.dwords[i].get(dword, 0) + 1
        return 0

    def log(self, *args, **kwargs):
        # todo: proper logging
        print(*args,file=sys.stderr, **kwargs)

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


    def hd_offset(self, off, width):
        return f'{self.term.normal}{off:0{width}x}:  '

    def get_heatmap_colorcode(self, value):
        r,g,b = heatMapColor(value)
        # ESC[48;2;⟨r⟩;⟨g⟩;⟨b⟩
        colorcode = self.term.on_color_rgb(r,g,b)
        return colorcode + self.term.black

    def printHeatMapValue(self, text, value):
        bgcolorcode = self.get_heatmap_colorcode(value)

        print(f'{bgcolorcode}{self.term.black}{text}{self.term.normal}', end='')

    def show_heatmap(self, selected=0, levels=8):
        c = 0
        offwidth = self.get_off_width()
        selected_color = self.term.white + self.term.on_black()
        for offset in sorted(self.fields.keys()):
            field = self.fields[offset]

            n = len(field.freqs.keys())
            if (c % 0x10) == 0:
                print(self.hd_offset(c, offwidth), end='')

            bytes_left = 16 - (c%16)
            bytes_to_print = []
            if n == 1:
                v = list(field.freqs.keys())[0]
                bs = v.to_bytes(field.length, byteorder=self.endianness)
                bytes_to_print.extend(f'{b:02x}' for b in bs)
            else:
                bytes_to_print.extend(['xx'] * field.length)

            level = math.floor(math.log2(n))
            if level >= levels:
                level = levels - 1

            if offset <= selected < offset + field.length:
                colorcode = selected_color
            else:
                colorcode = self.get_heatmap_colorcode(level/levels)


            fieldstr = '[' + '  '.join(bytes_to_print[:bytes_left])

            nextline = bytes_to_print[bytes_left:]
            if nextline:
                fieldstr += (' \n' + self.hd_offset(c+bytes_left, offwidth)
                             + colorcode + ' '
                             + '  '.join(nextline))
            fieldstr += ']'

            print(f'{colorcode}{fieldstr}{self.term.normal}', end='')

            c += field.length
            if (c % 0x10) == 0:
                print()

        if c % 0x10:
            print('\n' + self.hd_offset(c, offwidth))

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

        self.fields = {}
        self.fieldoffset_by_byteoffset = {}
        #offset = self.packet_offset
        offset = 0
        while offset < len(self.bytes.keys()) - 4:

            # check the next four bytes to see if they change together
            b_count = min(len(self.bytes[o].keys()) for o in range(offset,offset+4))
            w_count = min(len(self.words[o].keys()) for o in range(offset, offset+3))
            d_count = len(self.dwords[offset].keys())

            if d_count <= w_count <= b_count:
                width = 4
                values = self.dwords[offset]
            else:
                # check the next two bytes to see if they change together
                b_count = min(len(self.bytes[o].keys()) for o in range(offset,offset+1))
                w_count = len(self.words[offset].keys())
                if w_count <= b_count:
                    width = 2
                    values = self.words[offset]
                else:
                    width = 1
                    values = self.bytes[offset]

            self.fields[offset] = Field(offset, width, values)
            # cache the field starting offset for any given position in the packet
            for i in range(width):
                self.fieldoffset_by_byteoffset[offset + i] = offset
            offset += width

    def show_likely_fields(self):
        for offset in sorted(self.fields.keys()):
            field = self.fields[offset]
            typestr="Unknown"
            if field.length == 1:
                typestr = "Byte"
            elif field.length == 2:
                typestr = "Word"
            elif field.length == 4:
                typestr = "DWord"

            print(f'{field.offset:#02x}: likely {typestr}')
            for val, freq in field.freqs.items():
                print(f"  {val:#0{field.length * 2}x} ({freq})")


    def show_strings(self):
        self.log('not implemented')
        pass

    def get_off_width(self):
        return math.ceil(len(self.bytes).bit_length() / 4)

    def interactive(self):
        """Display an interactive TUI"""
        term = self.term
        maxoff = len(self.bytes) - 2
        selected_offset = 0
        with term.fullscreen(), term.cbreak():
            key = ''
            while key.lower() != 'q':
                self.log(f"selected: {selected_offset}; max: {maxoff}")
                sel_field = self.fields[selected_offset]
                print(term.home)
                self.show_heatmap(selected=selected_offset)
                key = term.inkey()
                if key == 'h' or key.code == term.KEY_LEFT:
                    selected_offset = selected_offset - 1
                if key == 'l' or key.code == term.KEY_RIGHT:
                    selected_offset = selected_offset + sel_field.length
                if key == 'j' or key.code == term.KEY_DOWN:
                    selected_offset = selected_offset + 0x10
                if key == 'k' or key.code == term.KEY_UP:
                    selected_offset = selected_offset - 0x10

                if selected_offset < 0:
                    selected_offset = 0
                if selected_offset > maxoff:
                    self.log(f'{selected_offset} > {maxoff}')
                    self.log(f'setting = {maxoff}')
                    selected_offset = maxoff

                selected_offset = self.fieldoffset_by_byteoffset[selected_offset]

def main():
    parser = argparse.ArgumentParser("Fieldinator")
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
    parser.add_argument('--protocol', '-p', help='protocol layer to start at instead of whole frame')
    parser.add_argument('--protocol-field', help='Name of field within protocol to use for analysis instead of the whole frame')


    args = parser.parse_args()
    fd = Fieldinator(args.input, args.filter, args.packet_offset, args.verbose,
            args.endian, args.protocol, args.protocol_field)
    #fd.show_heatmap()
    fd.interactive()
    if args.fields:
        fd.show_likely_fields()
    if args.bytes:
        fd.show_bytes()
    if args.words:
        fd.show_words()
    if args.dwords:
        fd.show_dwords()
    if args.strings:
        fd.show_strings()

if __name__ == '__main__':
    main()
