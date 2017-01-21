from elftools.elf.elffile import ELFFile

# this tool uses VMA offsets NOT file offsets
# so you don't need to translate them, this tool does it for you
# BUT note: I assume that we're patching stuff contained in one segment


import sys
import argparse
import shutil


bytes = {'thumb2': b'\x00\xbf',
         'thumb4': b'\x00\x80\xaf\xf3', 'arm': b'\x00\xf0\x20\xe3'}


parser = argparse.ArgumentParser(
    description="Insert NOP's into ARM executables at a given VMA offset range")

parser.add_argument('file', help='Input file')
parser.add_argument('output', help='Output file')
parser.add_argument('start',
                    help="Insert nops starting from this VMA offset (may be 0x...)")
parser.add_argument('end',
                    help="... until this offset <exclusive> (may be 0x...)")
parser.add_argument('-t', '--type', default='thumb2', choices=list(bytes.keys()),
                    help="NOP instruction type. Default is thumb2 (0xbf00)")

args = parser.parse_args()


if args.file != args.output:
    shutil.copyfile(args.file, args.output)


start = int(args.start, 16) if 'x' in args.start else int(args.start)
end = int(args.end, 16) if 'x' in args.end else int(args.end)


with open(args.output, 'r+b') as f:
    elf = ELFFile(f)

    prev_addr = prev_offset = offset_delta = written_nops = 0

    for x in range(elf.num_sections()):
        s = elf.get_section(x)

        if s['sh_addr'] < prev_addr:
            break

        if s['sh_addr'] > start:
            offset_delta = prev_offset - prev_addr
            break

        prev_addr = s['sh_addr']
        prev_offset = s['sh_offset']

    curr = start

    while curr < end:
        f.seek(curr + offset_delta)
        f.write(bytes[args.type])

        curr += len(bytes[args.type])
        written_nops += 1

    print('%d NOPs written' % written_nops)
