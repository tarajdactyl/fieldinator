#!/usr/bin/env python3

import argparse
import math

def print_color(r,g,b):
    normalcode = '\x1b[0m'
    # ESC[48;2;⟨r⟩;⟨g⟩;⟨b⟩
    colorcode = f'\x1b[48;2;{r};{g};{b}m'
    print(f"{colorcode}{r:02x}{g:02x}{b:02x}{normalcode}")

def print_colors(base, steps):
    if base == 0:
        base = 0xffffff
    base_b = base & 0xff
    base_g = (base & 0xff00) >> 8
    base_r = (base & 0xff0000) >> 16
    #print_color(base_r,base_g,base_b)
    #print(f"{base_r:x} {base_g:x} {base_b:x}")
    base_t = (base_r, base_g, base_b)

    maxidx = base_t.index(max(base_t))

    r_ratio = base_r / base_t[maxidx]
    b_ratio = base_b / base_t[maxidx]
    g_ratio = base_g / base_t[maxidx]


    inc = math.ceil(0xff/steps)
    step = inc
    while step < 256:
        #print(hex(step))
        r = math.floor(r_ratio * step + .5)
        b = math.floor(b_ratio * step + .5)
        g = math.floor(g_ratio * step + .5)
        print_color(r,g,b)

        step += inc


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("hexcode", type=lambda x: int(x, 0),
            help='The "base" color to use for the colorscheme')
    parser.add_argument("--steps", "-s",
            help='number of steps to use', default=16, type=int)
    args = parser.parse_args()
    print_colors(args.hexcode, args.steps)
