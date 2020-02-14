# Unicorn Engine
- Unicorn is a lightweight multi-platform, multi-architecture CPU emulator framework.
- Uses a heavily modified version of Qemu to support multiple architectures.
- Authors N.GUYEN Anh Quyn and DANG Hoang Vu.

## Resources
 - Official Site [[link](https://www.unicorn-engine.org/)]
 - Introduction BlackHat [[link](https://www.unicorn-engine.org/BHUSA2015-unicorn.pdf)]
 - Source Code [[link](https://github.com/unicorn-engine/unicorn)]
 - x86 Constant [[link](https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/unicorn/x86_const.py)]
 - `unicorn.h` [[link](https://github.com/unicorn-engine/unicorn/blob/master/include/unicorn/unicorn.h)]
 - `unicorn.py` [[link](https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/unicorn/unicorn.py)]
 - Eternal Stories' Unicorn Engine tutorial [[link](http://eternal.red/2018/unicorn-engine-tutorial/)]
 - Tomori Nao's Unicorn Engine Reference (Unofficial) [[link](https://hackmd.io/s/rJTUtGwuW)]

## Unicorn Engine High Level Usage & Core Concepts
The following is a list of high-level usage and core concepts of using the Unicorn Engine.

 1. Initialize Unicorn Instance.
 2. Read and write memory.
 3. Read and write registers.
 4. Start and stop emulation.
 5. Memory and hook management.
 6. Instrument user-defined callbacks.
 7. Exit Unicorn Instance

Each usage and concept is explored below with brief descriptions and example code.

### 1. Initialize Unicorn Instance
To initialize the Unicorn class the API `Uc(UC_ARCH, UC_MODE)` is used. The first argument is the hardware architecture type. The second argument is the hardware mode type and/or endianness. The following are the available architecture type.

- `UC_ARCH_ARM` // ARM architecture (including Thumb, Thumb-2)
- `UC_ARCH_ARM64`  // ARM-64, also called AArch64
- `UC_ARCH_MIPS`   // Mips architecture
- `UC_ARCH_X86`    // X86 architecture (including x86 & x86-64)
- `UC_ARCH_PPC`    // PowerPC architecture (currently unsupported)
- `UC_ARCH_SPARC`  // Sparc architecture
- `UC_ARCH_M68K`   // M68K architecture
- `UC_ARCH_MAX`

The following is the available hardware types. The comments are from `unicorn.h`.

###### Endianness
- `UC_MODE_LITTLE_ENDIAN` // little-endian mode (default mode)
- `UC_MODE_BIG_ENDIAN`  // big-endian mode

###### Arm
 - `UC_MODE_ARM` // ARM mode
 - `UC_MODE_THUMB` // THUMB mode (including Thumb-2)
 - `UC_MODE_MCLASS` // ARM's Cortex-M series (currently unsupported)
 - `UC_MODE_V8` // ARMv8 A32 encodings for ARM (currently unsupported)

###### Mips
 - `UC_MODE_MICRO`  // MicroMips mode (currently unsupported)
 - `UC_MODE_MIPS3`  // Mips III ISA (currently unsupported)
 - `UC_MODE_MIPS32R6`  // Mips32r6 ISA (currently unsupported)
 - `UC_MODE_MIPS32`  // Mips32 ISA
 - `UC_MODE_MIPS64` // Mips64 ISA

###### x86 / x64
 - `UC_MODE_16`  // 16-bit mode
 - `UC_MODE_32` // 32-bit mode
 - `UC_MODE_64` // 64-bit mode

###### ppc
 - `UC_MODE_PPC32` // 32-bit mode (currently unsupported)
 - `UC_MODE_PPC64` // 64-bit mode (currently unsupported)
 - `UC_MODE_QPX` // Quad Processing eXtensions mode (currently unsupported)

###### sparc
 - `UC_MODE_SPARC32` // 32-bit mode
 - `UC_MODE_SPARC64` // 64-bit mode
 - `UC_MODE_V9` // SparcV9 mode (currently unsupported)

There are many different combinations of architecture and hardware types. The Unicorn Engine Python bindings directory [[link](https://github.com/unicorn-engine/unicorn/tree/master/bindings/python)] contains several example scripts. All the examples have the pattern `sample_.*.py`.

###### Example 1
The following example uses pefile to get the hardware type for an `x86` architecture type.
```Python
from __future__ import print_function
import pefile
from unicorn import *
from unicorn.x86_const import *

IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_AMD64 = 0x8664


def read_data(file_path):
    with open(file_path, "rb") as infile:
        return infile.read()


def is_x86_machine(pe_data):
    """
    Is executable 32 bit
    :param pe_data:
    :return: True if 32 bit, False if 64 bit, None if other
    """
    try:
        pe = pefile.PE(data=pe_data)
    except Exception as e:
        print("ERROR: pefile load error %s") % (e)
        return
    if pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_I386:
        x86_machine = True
    elif pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_AMD64:
        x86_machine = False
    return x86_machine


pe_data = read_data("data.bin")
if is_x86_machine(pe_data):
    # Initialize unicorn instance
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    print("32-bit")
else:
    # UC_MODE_LITTLE_ENDIAN is the default mode
    # UC_MODE_LITTLE_ENDIAN has been included to show usage of defining endianness
    uc = Uc(UC_ARCH_X86, UC_MODE_64 | UC_MODE_LITTLE_ENDIAN)
    print("64-bit")
```
`uc` is the unicorn instance.


### Read and write memory
Before memory can read to or write to, the memory needs to be mapped. To map memory the APIs `uc.mem_map(address, size, perms=uc.UC_PROT_ALL)` and `uc.mem_map_ptr(address, size, perms, ptr)` are used. The following memory protections are available.

 - `UC_PROT_NONE`
 - `UC_PROT_READ`
 - `UC_PROT_WRITE`
 - `UC_PROT_EXEC`
 - `UC_PROT_ALL`

To protect a range of memory the API `uc.mem_protect(address, size, perms=uc.UC_PROT_ALL)` is used. To unmap memory the API `uc.mem_unmap(address, size)` is used. Once the memory is mapped it can be written to by calling `uc.mem_write(address, data)`. To read from the allocated memory `uc.mem_read(address, size)` is used.

###### Example 2
The following code creates a Unicorn Instance assigned to `uc`. An address of `0x00300000` is assigned to `stack_base` and a size of `0x00100000` is assigned to `stack_size`. The address is then mapped by calling `uc.mem_map(stack_base, stack_size)`. Once the memory is mapped null bytes (`\x00`) are written to the memory.

```python
uc = Uc(UC_ARCH_X86, UC_MODE_32)
stack_base = 0x00300000
stack_size = 0x00100000
uc.mem_map(stack_base, stack_size)
uc.mem_write(stack_base, "\x00" * stack_size)
```
### Read and Write Registers
Registers can be read by calling `uc.reg_read(reg_id, opt=None)`. The `reg_id` is defined in the appropriate architecture constant Python file in the Python bindings directory [[link](https://github.com/unicorn-engine/unicorn/tree/master/bindings/python/unicorn)].

 - `ARM-64` in `arm64_const.py`
 - `ARM` in `arm_const.py`
 - `M68K` in `m68k_const.py`
 - `MIPS` in `mips_const.py`
 - `SPARC` in `sparc_const.py`
 - `X86` in `x86_const.py`

To reference the constants, they must be first imported. In Example 1 the constants are imported by calling the following code.

```python
from unicorn.x86_const import *
```

To write the contents of a register `uc.reg_write(reg_id, value)` is used.

###### Example 3
The following code writes the stack base address stored in `stack_base` to the register `ESP` by calling `uc.reg_write(reg_id, value)`. `UC_X86_REG_ESP` is the `reg_id` for ESP. The register is then read by calling `uc.reg_read(reg_id, opt=None)`. The last argument in `reg_read` is optional and is left out in the example code.

```python
uc.reg_write(UC_X86_REG_ESP, stack_base + stack_size)
ebp = uc.reg_read(UC_X86_REG_EBP)
print("0x%x" % ebp)
```

### Start and Stop Emulation
To start the Unicorn Engine emulating the API `uc.emu_start(begin, until, timeout=0, count=0)` is called. The first function `start` is the first address that is emulated. The second argument `until` is the address (or above) that the Unicorn Engine stops emulating at. The argument `timeout=` is used to define the number of milliseconds that the Unicorn Engine executes until it times out. `UC_SECOND_SCALE * n` can be used to wait `n` number of seconds. The last argument `count=` can be used to define the number of instructions that are executed before the Unicorn Engine stops executing. If `count=` is zero or less than counting by the Unicorn Engine is disabled. To stop emulating the API `uc.emu_stop()` is used.

###### Example 4
Building off of the previous examples, the following code reads the Portable Executable (PE) entry point and then executes until the instruction pointer `EIP` is either 100 bytes away or past the address the entry point. If the Unicorn Engine hits an exception it is printed.

```python
entry_point = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
try:
    uc.emu_start(entry_point, entry_point + 100)
except Exception as e:
    print(e)
```

### Memory and Hook Management
The Unicorn Engine supports a wide arrange of hooks. The following describes each hook. The sentences in quotes were extracted from comments in `unicorn.h`. The hooks are inserted before the call to start the emulation. To add a hook the API `mu.hook_add(UC_HOOK_*, callback, user_data, begin, end, ...)`. The first two arguments are mandatory. The last three are optional and are usually populated with default values of `None, 1, 0, UC_INS`. To delete a hook the API `emu.hook_del(hook)` is used. To delete a hook it must be assigned to a variable. Please see the following code for an example. 

```python 
i = emu.hook_add(UC_HOOK_CODE, hook_code, None)
emu.hook_del(i)
```

The following covers each hook type with a minimal code example. 

##### UC_HOOK_INTR
 - "Hook all interrupt/syscall events"
 - `intno` is the interrupt number. 
 - `user_data` is user data supplied to the callback

###### Example Usage
```Python
def hook_intr(uc, intno, user_data):
    # only handle Linux syscall
    if intno != 0x80:
        print("got interrupt %x ???" %intno);
        uc.emu_stop()
        return
mu.hook_add(UC_HOOK_INTR, hook_intr)
```

##### UC_HOOK_INSN
 - "Hook a particular instruction - only a very small subset of instructions supported here"
 - Hooks three x86 instructions: `IN`, `OUT` and `SYSCALL` [[?](https://github.com/unicorn-engine/unicorn/issues/7)].  

###### Example Usage 
```Python
def hook_syscall(mu, user_data):
            rax = mu.reg_read(UC_X86_REG_RAX)
            if rax == 0x100:
                mu.reg_write(UC_X86_REG_RAX, 0x200)
            else:
                print('ERROR: was not expecting rax=%d in syscall' % rax)

mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
```

##### UC_HOOK_CODE
 - "Hook a range of code"
 - Hook is called before every instruction is executed.

###### Example Usage 
```python
def hook_code(uc, address, size, user_data):
    print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))

uc.hook_add(UC_HOOK_CODE, hook_code)
```

##### UC_HOOK_BLOCK
 - "Hook basic blocks"

###### Example Usage 
```python
 def hook_block(uc, address, size, user_data):
     print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size)

 uc.hook_add(UC_HOOK_BLOCK, hook_block)
 ```

##### UC_HOOK_MEM_* Generic Description
The rest of the hooks are related to the reading, fetching, writing and accessing of memory. They all start with `UC_HOOK_MEM_*`. Their callback all have the same arguments as seen below. 

```python
def hook_mem_example(uc, access, address, size, value, user_data):
    pass
```    
The second argument is `access`

```python 
UC_MEM_READ = 16
UC_MEM_WRITE = 17
UC_MEM_FETCH = 18
UC_MEM_READ_UNMAPPED = 19
UC_MEM_WRITE_UNMAPPED = 20
UC_MEM_FETCH_UNMAPPED = 21
UC_MEM_WRITE_PROT = 22
UC_MEM_READ_PROT = 23
UC_MEM_FETCH_PROT = 24
UC_MEM_READ_AFTER = 25
```

##### UC_HOOK_MEM_READ_UNMAPPED
 - "Hook for memory read on unmapped memory"

###### Example Usage
```python 
def hook_mem_read_unmapped(uc, access, address, size, value, user_data):
    pass
uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read_unmapped, None)
```
_Note_
The following hooks do not contain example code but the previous examples can be used as a skelton 

##### UC_HOOK_MEM_WRITE_UNMAPPED
 - "Hook for invalid memory write events"

##### UC_HOOK_MEM_FETCH_UNMAPPED
 - "Hook for invalid memory fetch for execution events"

##### UC_HOOK_MEM_READ_PROT
 - "Hook for memory read on read-protected memory"

##### UC_HOOK_MEM_WRITE_PROT
 - "Hook for memory write on write-protected memory"

##### UC_HOOK_MEM_FETCH_PROT
 - "Hook for memory fetch on non-executable memory"

##### UC_HOOK_MEM_READ
 - "Hook memory read events"

##### UC_HOOK_MEM_WRITE
 - "Hook memory write events"

##### UC_HOOK_MEM_FETCH
 - "Hook memory fetch for execution events"

##### UC_HOOK_MEM_READ_AFTER
 - "Hook memory read events, but only successful access. he callback will be triggered after successful read"

### Instrument User-Defined Callbacks
Instrument callbacks are used to read, write or control the flow of the instrumentation. The Memory and Hook Management section contained a number of example user callbacks. 

### Uniconn Initialization Class
The following class can be used to initialize memory (code, data, stack, etc) before using Unicorn. It is designed for the x86/x86_64 code or executables. It relies on PEFile to load the executable. An example on how to use the code can be found in Usage Example. 

```python
from __future__ import print_function
import pefile, collections
from unicorn import *
from unicorn.x86_const import *

IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_AMD64 = 0x8664

"""
    Usage Example: 
        # run shellcode 
        # read bytes 
        instructions = b"\x90\x90\x90\x90""
        # init unicorn instance, allocate memory, create stack, etc 
        tt = InitUnicorn(instructions)
        # emulate code standard unicorn start arguments
        tt.mu.emu_start(tt.code_base, tt.code_base + len(instructions))
        # read register value 
        r_eip = tt.mu.reg_read(UC_X86_REG_EIP)
        print("0x%x" % r_eip)
        
        # read 32-bit executable 
        data = open("bad_file.exe", "rb").read()
        # options data, type_pe=False, bit=32, debug=False)
        tt = InitUnicorn(data, type_pe=True, debug=True)
        
        try:
            # Verbose, if it works set DEBUG False 
            tt.DEBUG = True
            # emulate virtual address 
            tt.mu.emu_start(0x0405490, 0x0405490 + 0x1C)
            r_eax = tt.mu.reg_read(UC_X86_REG_EAX)
            print("0x%x" % r_eax)
        
        except Exception as e:
            print("0x%x" % (tt.mu.reg_read(UC_X86_REG_ESP)))
            print(e)
"""


class InitUnicorn(object):
    def __init__(self, data, type_pe=False, bit=32, debug=False):
        self.code_base = 0x00100000
        self.DEBUG = debug
        # pe check
        if type_pe:
            self.load_pe(data)
            if self.pe:
                self.init_unicorn()
                self.base = self.pe.OPTIONAL_HEADER.ImageBase
                self.map_pe_mem()
                self.create_stack()
        else:
            if bit == 32:
                self.is_x86_machine = True
            else:
                self.is_x86_machine = False
            self.init_unicorn()
            self.map_data(data)
            self.create_stack()
        if self.DEBUG:
            self.add_debug()

    def create_stack(self):
        if self.is_x86_machine:
            self.is_x86_machine = True
            self.stack_base = 0x00300000
            self.stack_size = 0x00100000
        else:
            self.is_x86_machine = False
            self.stack_base = 0xffffffff00000000
            self.stack_size = 0x0000000000100000
        self.mu.mem_map(self.stack_base, self.stack_size)
        self.mu.mem_write(self.stack_base, b"\x00" * self.stack_size)
        if self.is_x86_machine:
            self.mu.reg_write(UC_X86_REG_ESP, self.stack_base + 0x800)
            self.mu.reg_write(UC_X86_REG_EBP, self.stack_base + 0x1000)
        else:
            self.mu.reg_write(UC_X86_REG_RSP, self.stack_base + 0x8000)
            self.mu.reg_write(UC_X86_REG_RBP, self.stack_base + 0x10000)

    def init_unicorn(self):
        if self.is_x86_machine:
            self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
        else:
            self.mu = Uc(UC_ARCH_X86, UC_MODE_64)

    def map_data(self, data):
        self.mu.mem_map(self.code_base, 0x10000)
        self.mu.mem_write(self.code_base, data)

    '''
    Modified version of Willi Ballenthin's code
        https://github.com/williballenthin/python-vb/blob/master/vb/analyzer.py#L115
    '''
    def load_pe(self, pe_data):
        try:
            self.pe = pefile.PE(data=pe_data)
            if self.pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_I386:
                self.is_x86_machine = True
            elif self.pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_AMD64:
                self.is_x86_machine = False

        except Exception as e:
            self.pe = None
            if self.DEBUG:
                print("ERROR: pefile load error %s") % (e)
            return

    def map_pe_mem(self):
        # map executable memory
        align_size = self.pe.OPTIONAL_HEADER.SectionAlignment
        for section in self.get_map():
            self.mu.mem_map(section.va, self.align(section.size, align_size))
            temp_bytes = self.get_bytes(section.va, section.size)
            self.mu.mem_write(section.va, temp_bytes)

    def get_map(self):
        MapEntry = collections.namedtuple('MapEntry', ['va', 'size'])
        ret = []
        for section in self.pe.sections:
            rva = section.VirtualAddress
            va = self.base + rva
            size = section.Misc_VirtualSize
            ret.append(MapEntry(va, size))
        return ret

    def get_bytes(self, va, length):
        rva = va - self.base
        return self.pe.get_data(rva, length)

    def va(self, rva):
        return self.base + rva

    def rva(self, va):
        return va - self.base

    def align(self, value, alignment):
        if value % alignment == 0:
            return value
        return value + (alignment - (value % alignment))

    def add_debug(self):
     """For Debugging Use Only"""
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code)
        self.mu.hook_add(UC_HOOK_INSN, self.hook_call, None, 1, 0, UC_X86_INS_CALL)
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid)

    def hook_code(self, uc, address, size, user_data):
        """For Debugging Use Only"""
        print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' % (address, size))

    def hook_call(self, uc, address, size, user_data):
        """For Debugging Use Only"""
        print('>>> Call instruction at 0x%x, instruction size = 0x%x' % (address, size))

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
     """For Debugging Use Only"""
        eip = uc.reg_read(UC_X86_REG_EIP)
        if access == UC_MEM_WRITE:
            print("invalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" % (address, eip, size, value))
        if access == UC_MEM_READ:
            print("invalid READ of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        if access == UC_MEM_FETCH:
            print("UC_MEM_FETCH of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        if access == UC_MEM_READ_UNMAPPED:
            print("UC_MEM_READ_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        if access == UC_MEM_WRITE_UNMAPPED:
            print("UC_MEM_WRITE_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        if access == UC_MEM_FETCH_UNMAPPED:
            print("UC_MEM_FETCH_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        if access == UC_MEM_WRITE_PROT:
            print("UC_MEM_WRITE_PROT of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        if access == UC_MEM_FETCH_PROT:
            print("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        if access == UC_MEM_FETCH_PROT:
            print("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        if access == UC_MEM_READ_AFTER:
            print("UC_MEM_READ_AFTER of 0x%x at 0x%X, data size = %u" % (address, eip, size))
        return False
```



## References
 - https://manybutfinite.com/post/journey-to-the-stack/
 - https://docs.microsoft.com/en-us/cpp/build/stack-usage?view=vs-2017
