'''
A tool to find references to string constants in 32bit ARM executables that deals with position independent stuff.

Original tool written by: Rafal Kolanski (xaph.net) 2010
Original tool can be found here: https://www.mobileread.com/forums/showthread.php?t=80872
Modified by zb3 2017/2022

Yes, the code needs to be refactored.

'''

import os
import sys
import subprocess
import re
import argparse

from collections import defaultdict

parser = argparse.ArgumentParser(description='Dissassemble a given 32bit ARM executable, showing references to string constants in comments.')

parser.add_argument('file', help='Program to disassemble')
parser.add_argument('-cc', '--cross-compile', default=None,
                    help='Path with prefix to objdump. Overwrites CROSS_COMPILE environment variable')
parser.add_argument('-ft', '--force-thumb', action='store_true',
                    help='Force THUMB mode')
parser.add_argument('-d', '--demangle', action='store_true',
                    help='Pass the -C option to objdump')
parser.add_argument('-s', '--start', default='0',
                    help="Search start virtual offset (may be 0x...)")
parser.add_argument('-e', '--end', default='0',
                    help="Search end virtual offset (may be 0x...)")
parser.add_argument('-z', '--disassemble-zeroes', action='store_true',
                    help="Do not skip blocks of zeroes when disassembling")
parser.add_argument('-D', '--disassemble-all', action='store_true',
                    help="Disassemble all sections")
parser.add_argument('-l', '--list-references', action='store_true',
                    help="Display only references to strings with their addresses, without code")
parser.add_argument('-a', '--display-all', action='store_true',
                    help="Display computed values in registers even if they don't point at any string")
parser.add_argument('-nr', '--no-require-start', action='store_true',
                    help="Don't require a null byte before the string starts")
parser.add_argument('-b', '--show-on-branch', action='store_true',
                    help="Display string literals on branch instructions (requires -c)")

args = parser.parse_args()

BASE = ''
if args.cross_compile:
    BASE = args.cross_compile
elif 'CROSS_COMPILE' in os.environ:
    BASE = os.environ['CROSS_COMPILE']


force_thumb = args.force_thumb
addr_start = int(args.start, 16) if 'x' in args.start else int(args.start)
addr_end = int(args.end, 16) if 'x' in args.end else int(args.end)
display_code = not args.list_references
display_all = args.display_all
demangle = args.demangle
disassemble_all = args.disassemble_all
disassemble_zeroes = args.disassemble_zeroes
require_start = not args.no_require_start
show_on_branch = args.show_on_branch  # not as good as I thought...


# regex matching an asm line in objdump with default settings
instr_re = re.compile(
    r'\W+(?P<addr>[0-9a-f]+):\W+(?P<word>[0-9a-f]+([ ][0-9a-f]+)?)\W+(?P<instr>[^;()]*)')
offset_re = re.compile(
    r'(?P<vmoffset>[0-9a-f]+) <[^>]+> \(File Offset: (?P<offset>0x[0-9a-f]+)\)')
objdump = BASE + 'objdump'



def load_word(memory, addr):
    '''Load 32-bit word from file'''

    return (memory[addr + 3] << 24) + (memory[addr + 2] << 16) + (memory[addr + 1] << 8) + memory[addr]


def load_cstring(memory, addr):
    '''Try to load a C (NUL-terminated) string from memory
    
    String may contain only ascii chars (and newline/tab) and may not be empty.
    '''
    if require_start and addr - 1 < len(memory) and memory[addr - 1]:
        return None

    start = addr

    while 1:
        if addr >= len(memory):
            return None

        code = memory[addr]

        if code == 0:
            return memory[start:addr].decode('iso-8859-1') if start != addr else None

        if (code < 32 or code >= 127) and code != 10 and code != 9:
            return None

        addr += 1


def cstring_check(memory, instr_addr, addr):
    s = load_cstring(memory, addr)
    if s:
        if not display_code:
            print('%x:\t' % instr_addr, end='')
        else:
            print('; ', end='')

        print('STRING "%s"' % s, end='')

        if not display_code:
            print('')
            
    elif display_code and display_all:
        print('; val=%s' % hex(addr), end='')


def cstring_check_arg(memory, regs):
    to_print = []

    for reg in ('r0', 'r1', 'r2', 'r3', 'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'):
        s = load_cstring(memory, addr_to_offset(regs[reg]))

        if s:
            to_print.append(reg + '="' + s + '"')

    return ', '.join(to_print)

def is_branch(instr):
    if ' ' not in instr:
        return False

    op = instr[:instr.index(' ')]
    arg = instr[len(op) + 1:]

    if op.startswith('b') and not op.startswith(('bfc', 'bfi', 'bic', 'bkpt')):
        return True

    if op.startswith(('pop', 'ldm')) and 'pc' in arg:
        return True

    if arg.startswith(('pc,', 'pc!')):
        return True

    return False


def word_clamp(w): return w & 0xffffffff
def xword_clamp(w): return w & 0xffffffffffffffff


def disassemble(filename):
    args = [objdump]
    if force_thumb:
        args.extend(['-M', 'force-thumb'])
        
    if demangle:
      args.extend(['-C'])
        
    if disassemble_zeroes:
      args.extend(['-z'])

    args.extend(['-EL', '-F', '-D' if disassemble_all else '-d', filename])

    return subprocess.check_output(args).decode('iso-8859-1')



def pc(addr, thumb=True):
    """
    Get the PC register considering we are currently executing instruction at addr

    Note(v7-thumb): this function will not return correct address for operations involving memory
    (like LDR), because those operations always treat the value of PC as word-aligned
    For those operations, the value of PC is addr + 4-(addr%4)
    """
    return addr + (4 if thumb else 8)


# Extremely limited instruction interpretation
# IT blocks are not currently supported

def run_ldr_pc(regs, memory, instr, mo, base):
    m = re.match(r'ldr(?:[.][w])? (\w+), \[pc(?:, #(\d+))?](?!,)', instr)
    if not m:
        return None

    target = m.group(1)

    regs[target] = load_word(memory, int(mo.group('offset'), 16)) - base

    return target


def run_add(regs, memory, instr, aa):
    m = re.match(r'adds?(?:[.][w])? (\w+), (#?\w+)(, (#?\w+))?', instr)
    if not m:
        return None

    target = m.group(1)

    ret = 0
    if m.group(3):
        ret += regs[m.group(2)]
        op2 = m.group(4)
    else:
        ret += regs[m.group(1)]
        op2 = m.group(2)
    
    if op2[0] == '#':
        ret += int(op2[1:], 0)
    else:
        ret += regs[op2]
    
    if target[0] == 'x':
        ret = xword_clamp(ret)
    else:
        ret = word_clamp(ret)
    
    regs[target] = ret

    return target


def run_mov(regs, memory, instr):
    m = re.match(r'movs?(?:[.][w])? (\w+), (#?\w+)', instr)
    if not m:
        return None

    target = m.group(1)
    arg = m.group(2)
    if arg[0] != '#':
        regs[target] = regs[arg]
    else:
        regs[target] = int(arg[1:], 0)
        
    return target


# did I get this right?
def run_movt(regs, memory, instr):
    m = re.match(r'movt(?:[.][w])? (\w+), (#?\w+)', instr)
    if not m:
        return None

    target = m.group(1)
    arg = m.group(2)
    if arg[0] != '#':
        regs[target] = (regs[target] & 0xffff) | (regs[arg] << 16)
    else:
        regs[target] = (regs[target] & 0xffff) | (int(arg[1:], 0) << 16)

    return target
    
def run_adr(regs, memory, instr, mo):
    m = re.match(r'adrp? (\w+),', instr)
    if not m:
        return None
    
    target = m.group(1)
    arg = int(mo.group('offset'), 16)
    regs[target] = arg

    return target


def run(memory, m, m_offset, base=0):
    instr = m.group('instr').strip().replace('\t', ' ')

    addr = int(m.group('addr'), 16)

    # set pc for current instruction
    # for LDR instruction, it's not used as it needs
    # to be aligned
    # length of "word" group is 9 for 2byte thumb instructions
    regs['pc'] = pc(addr, False if len(m.group('word')) == 8 else True)

    ret = run_ldr_pc(regs, memory, instr, m_offset, base) or \
        run_add(regs, memory, instr, addr) or \
        run_mov(regs, memory, instr) or \
        run_movt(regs, memory, instr) or \
        run_adr(regs, memory, instr, m_offset)

    if ret and not show_on_branch:
        cstring_check(memory, addr, regs[ret])
    elif show_on_branch and is_branch(instr):
        strinfo = cstring_check_arg(memory, regs)
        if strinfo:
            print(' ; ' + strinfo, end='')


def runcode(memory, codestr):
    '''Run code from an objdump disassembly, skipping anything we don't know.'''
    # we'd want objdump to use file offsets everywhere, but this is not possible
    # let's approximate this by remembering the delta we see.
    # that should work, because we always have the offset for the ldr instruction
    # then add r1, pc, r1 will use this delta
    last_base = 0


    for line in codestr.split('\n'):
        if not line.strip():
            continue

        m = instr_re.match(line)

        if not m:
            if not addr_start and not addr_end and display_code:
              print(line)

            continue

        if addr_start and int(m.group('addr'), 16) < addr_start:
            continue
        if addr_end and int(m.group('addr'), 16) >= addr_end:
            break

        if display_code:
            print(line, end='')

        m_offset = offset_re.search(line)
        if m_offset:
            last_base = int(m_offset.group('vmoffset'), 16) - int(m_offset.group('offset'), 16)

        run(memory, m, m_offset, base=last_base)

        if display_code:
            print('')

class RegisterDict:
    def __init__(self):
        self.r = defaultdict(int)
    
    def __setitem__(self, name, val):
        is_64 = name[0] == 'x'
        name = name.replace('w', 'x')
        self.r[name] = xword_clamp(val) if is_64 else word_clamp(val)
        
    def __getitem__(self, name):
        name = name.replace('w', 'x')
        return self.r[name]

   
   
def main():
    global mem, regs
    mem = None
    # regs = RegisterDict()
    regs = defaultdict(int)

    obj = args.file

    with open(obj, 'rb') as f:
        mem = f.read()

    runcode(mem, disassemble(obj))


if __name__ == "__main__":
    sys.exit(main())
