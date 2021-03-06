# arm-random-tools

These are tools I used to modify executables on my Android device, which were ARMv7 ones and most of the code was running in thumb mode...
They require python3, a toolchain and `pyelfstools`.

Of course, not included here is the awesome `hexedit` tool which I used to actually modify those executables.

Some things I did using these tools:
* Disable SELinux completely by modifying init
* Remove things like `PR_SET_NO_NEW_PRIVS` which prevented me from running SUID binaries
* Patch `adbd` to run as root in "production builds"

Patching binaries is IMO easier than recompiling the whole thing...


## ARM-stringref

This is a modification of [this](https://www.mobileread.com/forums/showthread.php?t=80872) tool written by Rafal Kolanski.
The purpose of this tool is to show references to string constants in the disassembly generated by `objdump`. It has to deal with position-independent code, which complicates this process. The original tool didn't work in my case but the concept of writting a partial interpreter was good, so I modified the tool and extended it's functionality to deal with more advanced `objdump` syntax. However, you'll probably need to do the same, because chances this will work for you without modifications re not big :)

Note that this program assumes instructions are in thumb mode.

```
usage: arm-stringref.py [-h] [-cc CROSS_COMPILE] [-nt] [-s START] [-e END]
                        [-l] [-nr] [-b]
                        file

Dissassemble a given 32bit ARM executable, showing references to string
constants in comments.

positional arguments:
  file                  Program to disassemble

optional arguments:
  -h, --help            show this help message and exit
  -cc CROSS_COMPILE, --cross-compile CROSS_COMPILE
                        Path with prefix to objdump. Overwrites CROSS_COMPILE
                        environment variable
  -nt, --no-force-thumb
                        Don't force THUMB mode (forced by default)
  -s START, --start START
                        Search start virtual offset (may be 0x...)
  -e END, --end END     Search end virtual offset (may be 0x...)
  -l, --list-references
                        Display only references to strings with their
                        addresses, without code
  -nr, --no-require-start
                        Don't require a null byte before the string starts
  -b, --show-on-branch  Display string literals on branch instructions
                        (requires -c)

```

### Example

Turn this:

``` 
    d584:	4832      	ldr	r0, [pc, #200]	; (0xd650)
    d586:	4933      	ldr	r1, [pc, #204]	; (0xd654)
    d588:	4478      	add	r0, pc
    d58a:	4401      	add	r1, r0
    d58c:	2006      	movs	r0, #6
    d58e:	f004 f97f 	bl	0x11890
    d592:	f013 f9ed 	bl	0x20970
    d596:	f1b0 3fff 	cmp.w	r0, #4294967295	; 0xffffffff
    d59a:	dd38      	ble.n	0xd60e
    d59c:	2001      	movs	r0, #1
    d59e:	f010 f8a9 	bl	0x1d6f4
    d5a2:	492d      	ldr	r1, [pc, #180]	; (0xd658)
    d5a4:	482d      	ldr	r0, [pc, #180]	; (0xd65c)
    d5a6:	4a2e      	ldr	r2, [pc, #184]	; (0xd660)
    d5a8:	4479      	add	r1, pc
    d5aa:	4408      	add	r0, r1
    d5ac:	4411      	add	r1, r2
    d5ae:	f004 fc6f 	bl	0x11e90
```

Into this:

```
    d584:       4832            ldr     r0, [pc, #200]  ; (0xd650)
    d586:       4933            ldr     r1, [pc, #204]  ; (0xd654)
    d588:       4478            add     r0, pc
    d58a:       4401            add     r1, r0; STRING "Loading SELinux policy...
"
    d58c:       2006            movs    r0, #6
    d58e:       f004 f97f       bl      0x11890
    d592:       f013 f9ed       bl      0x20970
    d596:       f1b0 3fff       cmp.w   r0, #4294967295 ; 0xffffffff
    d59a:       dd38            ble.n   0xd60e
    d59c:       2001            movs    r0, #1
    d59e:       f010 f8a9       bl      0x1d6f4
    d5a2:       492d            ldr     r1, [pc, #180]  ; (0xd658)
    d5a4:       482d            ldr     r0, [pc, #180]  ; (0xd65c)
    d5a6:       4a2e            ldr     r2, [pc, #184]  ; (0xd660)
    d5a8:       4479            add     r1, pc
    d5aa:       4408            add     r0, r1; STRING "/sys/fs/selinux/checkreqprot"
    d5ac:       4411            add     r1, r2; STRING "0"
    d5ae:       f004 fc6f       bl      0x11e90
```

By doing this:

```
python arm-stringref.py -cc '/path/to/toolchain/prefix-' /android/init -s 0xd584 -e 0xd5b0
```

## noper

This program is very simple - it just inserts NOP instructions at a given virtual memory range.

```
usage: noper.py [-h] [-t {thumb2,thumb4,arm}] file output start end

Insert NOP's into ARM executables at a given VMA offset range

positional arguments:
  file                  Input file
  output                Output file
  start                 Insert nops starting from this VMA offset (may be
                        0x...)
  end                   ... until this offset <exclusive> (may be 0x...)

optional arguments:
  -h, --help            show this help message and exit
  -t {thumb2,thumb4,arm}, --type {thumb2,thumb4,arm}
                        NOP instruction type. Default is thumb2 (0xbf00)
```

### Example

Turn program containing this:

``` 
    d58e:	f004 f97f 	bl	0x11890
    d592:	f013 f9ed 	bl	0x20970
    d596:	f1b0 3fff 	cmp.w	r0, #4294967295	; 0xffffffff
    d59a:	dd38      	ble.n	0xd60e
    d59c:	2001      	movs	r0, #1
    d59e:	f010 f8a9 	bl	0x1d6f4
```

Into program containing this: (note this example doesn't make any sense)

``` 
    d58e:	f004 f97f 	bl	0x11890
    d592:	f013 f9ed 	bl	0x20970
    d596:	bf00      	nop
    d598:	bf00      	nop
    d59a:	bf00      	nop
    d59c:	2001      	movs	r0, #1
    d59e:	f010 f8a9 	bl	0x1d6f4
```

By running this:
```
python noper.py inputfile outputfile 0xd596 0xd59c
```