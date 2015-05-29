#!/usr/bin/env python
#
##########################################################################
# Copyright (C) 2015 Mark J. Blair, NF6X
#
# This file is part of dismantler.
#
#  dismantler is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  dismantler is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with dismantler.  If not, see <http://www.gnu.org/licenses/>.
##########################################################################

"""Define class for ROM image containing Intel 8080 code to be disassembled."""

import rom_base
import util
import exceptions

_alu  = ['ADD', 'ADC', 'SUB ', 'SBC', 'ANA', 'XRA', 'ORA', 'CMP']
_alui = ['ADI', 'ACI', 'SUI ', 'SBI', 'ANI', 'XRI', 'ORI', 'CPI']
_cc   = ['NZ', 'Z', 'NC', 'C', 'PO', 'PE', 'P', 'M']
_r    = ['B', 'C', 'D', 'E', 'H', 'L', 'M', 'A']
_rp   = ['B', 'D', 'H', 'SP']
_rp2  = ['B', 'D', 'H', 'PSW']

# Default label map
default_labels = {0x0000:'RST0', 0x0008:'RST1', 0x0010:'RST2', 0x0018:'RST3',
                  0x0020:'RST4', 0x0028:'RST5', 0x0030:'RST6', 0x0038:'RST7'}

# Default entry points
default_entries = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38]

# There are no default port names
default_ports = {}

class rom_8080(rom_base.rom_base):
    """ROM image containing Intel 8080 code to be disassembled."""


    # Pre-defined names for special auto-created labels
    special_labels = default_labels


    def __init__(self, rom, base_address=0,
                 label_map=default_labels,
                 port_map={}):
        """Object code item constructor.

        Keyword arguments:
        rom           -- Binary object code to be disassembled. Typically a bytearray.
        base_address  -- Memory address of first element of obj_code.
        label_map     -- Dictionary of label->address mappings.
        port_map      -- Dictionary of IO port name->address mappings (if applicable).
        """

        # We just override the default label_map value here.
        rom_base.rom_base.__init__(self, rom, base_address, label_map, port_map)

    def set_data8(self, address, access_addr=None):
        """Classify location as 8-bit data, Intel format.

        Keyword arguments:
        address     -- Address of location to reclassify.
        access_addr -- Address of instruction which triggered this
                       classification. Used for warning comment
                       if change indicates probable disassembly error.
        """

        self._set_data8_intel(address, access_addr)

    def set_data16(self, address, access_addr=None):
        """Classify location as 16-bit little-endian data, Intel format.

        Keyword arguments:
        address     -- Address of LSB location to reclassify.
        access_addr -- Address of instruction which triggered this
                       classification. Used for warning comment
                       if change indicates probable disassembly error.
        """

        self._set_data16_le_intel(address, access_addr)


    def set_vector(self, address, access_addr=None):
        """Classify location as containing a pointer to executable code and return contents.

        Function has same effect as set_data16(), but also returns contents
        of location so that the vector may be added to the entries list if
        desired.

        Keyword arguments:
        address     -- Address of LSB location to reclassify.
        access_addr -- Address of instruction which triggered this
                       classification. Used for warning comment
                       if change indicates probable disassembly error.

        Returns:
        Address contained at specified location.
        """

        return self._set_vector16_le_intel(address, access_addr)


    def disasm_single(self, address, create_label=True):
        """Disassemble a single instruction.

        Keyword arguments:
        address      -- Address of instruction to disassemble.
        create_label -- If True, create labels for possible address arguments.
                        This assumes that 16-bit constants are intended to be addresses.

        Returns:
        List of potential next instruction(s) to be executed."""

        idx = address - self.base_address
        assert (idx >= 0) and (idx <= self.rom_len)

        # Set/check classification
        if self.data_type[idx] is rom_base.type_instruction:
            # Location has already been disassembled.
            return []

        if self.data_type[idx] is rom_base.type_operand:
            # Trying to disassemble another instruction's operand
            self.comments[idx] += 'WARNING: Disassembling an operand. '

        if self.data_type[idx] in rom_base.data_types:
            # Trying to disassemble a data byte
            self.comments[idx] += 'WARNING: Disassembling data. '

        if self.data_type[idx] is rom_base.type_error:
            # Trying to disassemble an error
            self.comments[idx] += 'WARNING: Disassembling location flagged as error. '

        self.data_type[idx] = rom_base.type_instruction
        opcode     = self.rom[idx]
        next_addrs = []

        # Begin disassembling this location
    
        x = (opcode >> 6) & 0x03
        y = (opcode >> 3) & 0x07
        z = opcode & 0x07
        p = (y >> 1)
        q = y & 0x01

        if x == 0:
            if z == 0:
                # Relative jumps and assorted ops
                if y == 0:
                    self.disassembly[idx] = 'NOP'
                    next_addrs = [address + 1]
                else:
                    self.comments[idx] += 'ERROR: invalid opcode {:s} '.format(util.hex8_intel(opcode))
                    self.data_type[idx] = rom_base.type_error
                    next_addrs = [address + 1]

            elif z == 1:
                # 16-bit load immediate/add
                if q == 0:
                    word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                    self.data_type[idx+1] = rom_base.type_operand
                    self.data_type[idx+2] = rom_base.type_operand
                    self.disassembly[idx] = 'LXI  {:s}, {:s}'.format(_rp[p], util.hex16_intel(word))
                    next_addrs = [address + 3]
                else:
                    self.disassembly[idx] = 'DAD  {:s}'.format(_rp[p])
                    next_addrs = [address + 1]
            elif z == 2:
                # Indirect loading
                if q == 0:
                    if p <= 1:
                        self.disassembly[idx] = 'STAX {:s}'.format(_rp[p])
                        next_addrs = [address + 1]
                    elif p == 2:
                        word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                        self.data_type[idx+1] = rom_base.type_operand
                        self.data_type[idx+2] = rom_base.type_operand
                        self.disassembly[idx] = 'SHLD {:s}'.format(self._lookup_a16_intel(word, create_label, 'D_'))
                        self.set_data16(word, address)
                        next_addrs = [address + 3]
                    else:
                        word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                        self.data_type[idx+1] = rom_base.type_operand
                        self.data_type[idx+2] = rom_base.type_operand
                        self.disassembly[idx] = 'STA  {:s}'.format(self._lookup_a16_intel(word, create_label, 'D_'))
                        self.set_data8(word, address)
                        next_addrs = [address + 3]
                else:
                    if p <= 1:
                        self.disassembly[idx] = 'LDAX {:s}'.format(_rp[p])
                        next_addrs = [address + 1]
                    elif p == 2:
                        word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                        self.data_type[idx+1] = rom_base.type_operand
                        self.data_type[idx+2] = rom_base.type_operand
                        self.disassembly[idx] = 'LHLD {:s}'.format(self._lookup_a16_intel(word, create_label, 'D_'))
                        self.set_data16(word, address)
                        next_addrs = [address + 3]
                    else:
                        word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                        self.data_type[idx+1] = rom_base.type_operand
                        self.data_type[idx+2] = rom_base.type_operand
                        self.disassembly[idx] = 'LDA  {:s}'.format(self._lookup_a16_intel(word, create_label, 'D_'))
                        self.set_data8(word, address)
                        next_addrs = [address + 3]

            elif z == 3:
                #16-bit INC/DEC
                if q == 0:
                    self.disassembly[idx] = 'INX  {:s}'.format(_rp[p])
                else:
                    self.disassembly[idx] = 'DCX  {:s}'.format(_rp[p])
                next_addrs = [address + 1]

            elif z == 4:
                # 8-bit INC
                self.disassembly[idx] = 'INR  {:s}'.format(_r[y])
                next_addrs = [address + 1]

            elif z == 5:
                # 8-bit DEC
                self.disassembly[idx] = 'DCR  {:s}'.format(_r[y])
                next_addrs = [address + 1]

            elif z == 6:
                # 8-bit load immediate
                self.data_type[idx+1] = rom_base.type_operand
                self.disassembly[idx] = 'MVI  {:s}, {:s}'.format(_r[y], util.hex8_intel(self.rom[idx+1]))
                next_addrs = [address + 2]

            elif z == 7:
                # Assorted operations on accumulator/flags
                if y == 0:
                    self.disassembly[idx] = 'RLC'
                elif y == 1:
                    self.disassembly[idx] = 'RRC'
                elif y == 2:
                    self.disassembly[idx] = 'RAL'
                elif y == 3:
                    self.disassembly[idx] = 'RAR'
                elif y == 4:
                    self.disassembly[idx] = 'DAA'
                elif y == 5:
                    self.disassembly[idx] = 'CMA'
                elif y == 6:
                    self.disassembly[idx] = 'STC'
                else:
                    self.disassembly[idx] = 'CMC'
                next_addrs = [address + 1]

        elif x == 1:
            if (z == 6) and (y == 6):
                # Exception
                self.disassembly[idx] = 'HLT'
            else:
                self.disassembly[idx] = 'MOV  {:s}, {:s}'.format(_r[y],_r[z])
            next_addrs = [address + 1]

        elif x == 2:
            # Operate on accumulator and register/memory location
            self.disassembly[idx] = '{:4s} {:s}'.format(_alu[y],_r[z])
            next_addrs = [address + 1]

        elif x == 3:

            if z == 0:
                # Conditional return
                self.disassembly[idx] = 'R{:s}'.format(_cc[y])
                next_addrs = [address + 1]

            elif z == 1:
                # POP and various ops
                if q == 0:
                    self.disassembly[idx] = 'POP  {:s}'.format(_rp2[p])
                    next_addrs = [address + 1]
                else:
                    if p == 0:
                        self.disassembly[idx] = 'RET'
                        next_addrs = []
                    elif p == 1:
                        self.comments[idx] += 'ERROR: invalid opcode {:s} '.format(util.hex8_intel(opcode))
                        self.data_type[idx] = rom_base.type_error
                        next_addrs = []
                    elif p == 2:
                        self.disassembly[idx] = 'PCHL'
                        next_addrs = []
                    else:
                        self.disassembly[idx] = 'SPHL'
                        next_addrs = [address + 1]

            elif z == 2:
                # Conditional jump
                word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                self.data_type[idx+1] = rom_base.type_operand
                self.data_type[idx+2] = rom_base.type_operand
                self.disassembly[idx] = 'J{:2s}  {:s}'.format(_cc[y], self._lookup_a16_intel(word, create_label, 'J_'))
                next_addrs = [address + 3, word]
                self.add_xref(address, word)

            elif z == 3:
                # Assorted operations
                if y == 0:
                    word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                    self.data_type[idx+1] = rom_base.type_operand
                    self.data_type[idx+2] = rom_base.type_operand
                    self.disassembly[idx] = 'JMP  {:s}'.format(self._lookup_a16_intel(word, create_label, 'J_'))
                    next_addrs = [word]
                elif y == 1:
                    self.comments[idx] += 'ERROR: invalid opcode {:s} '.format(util.hex8_intel(opcode))
                    self.data_type[idx] = rom_base.type_error
                    next_addrs = []
                elif y == 2:
                    self.data_type[idx+1] = rom_base.type_operand
                    self.disassembly[idx] = 'OUT  {:s}'.format(self._lookup_port8_intel(self.rom[idx+1], create_label))
                    next_addrs = [address+2]
                elif y == 3:
                    self.data_type[idx+1] = rom_base.type_operand
                    self.disassembly[idx] = 'IN   {:s}'.format(self._lookup_port8_intel(self.rom[idx+1], create_label))
                    next_addrs = [address+2]
                elif y == 4:
                    self.disassembly[idx] = 'XTHL'
                    next_addrs = [address+1]
                elif y == 5:
                    self.disassembly[idx] = 'XCHG'
                    next_addrs = [address+1]
                elif y == 6:
                    self.disassembly[idx] = 'DI'
                    next_addrs = [address+1]
                else:
                    self.disassembly[idx] = 'EI'
                    next_addrs = [address+1]


            elif z == 4:
                # Conditional call
                word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                self.data_type[idx+1] = rom_base.type_operand
                self.data_type[idx+2] = rom_base.type_operand
                self.disassembly[idx] = 'C{:2s}  {:s}'.format(_cc[y], self._lookup_a16_intel(word, create_label, 'C_'))
                next_addrs = [address + 3, word]
                self.add_xref(address, word)

            elif z == 5:
                # PUSH and various ops
                if q == 0:
                    self.disassembly[idx] = 'PUSH {:s}'.format(_rp2[p])
                    next_addrs = [address + 1]
                else:
                    if p == 0:
                        word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                        self.data_type[idx+1] = rom_base.type_operand
                        self.data_type[idx+2] = rom_base.type_operand
                        self.disassembly[idx] = 'CALL {:s}'.format(self._lookup_a16_intel(word, create_label, 'C_'))
                        next_addrs = [address + 3, word]
                        self.add_xref(address, word)
                    else:
                        self.comments[idx] += 'ERROR: invalid opcode {:s} '.format(util.hex8_intel(opcode))
                        self.data_type[idx] = rom_base.type_error
                        next_addrs = []

            elif z == 6:
                # Operate on accumulator and immediate operand
                self.data_type[idx+1] = rom_base.type_operand
                self.disassembly[idx] = '{:4s} {:s}'.format(_alui[y],util.hex8_intel(self.rom[idx+1]))
                next_addrs = [address + 2]
                pass

            elif z == 7:
                # Restart
                self.disassembly[idx] = 'RST  {:d}'.format(y)
                next_addrs = [y*8]
                self.add_xref(address, y*8)

        return next_addrs


    def disassemble(self, entries=default_entries,
                    create_labels = True, single_step=False, valid_range=None,
                    breakpoints=[], vectors=[]):
        """Disassemble code, starting at specified entry point address(es).

        Keyword arguments:

        entries     -- List of entry point addresses at which to begin disassembly.
                       These shall be memory addresses, not array indices.

        create_labels -- Create labels for referenced memory locations

        single_step   -- If True, do not proceed beyond specified addresses in entries.
                         By default, continue disassembly recursively, following all
                         branches with computable destination addresses.

        valid_range   -- If specified, a tuple of (min_address, max_address) specifying
                         valid range of addresses to disassemble. May be used, for
                         example, to limit disassembly to a range of addresses shown
                         in a memory dump window.

        breakpoints   -- If specified, a list of addresses at which disassembly will
                         be stopped. Intended to be used to guide the disassembler in
                         cases where it gets confused about the program structure, in
                         conjunction with the entries argument.

        vectors       -- If specified, a list of addresses which are assumed to contain
                         pointers to executable code. Pointers are subject to label creation
                         and substitution, and will be added to entries list for disassembly.
        """

        # We are just changing the default entries argument value here, to default
        # to the RST intruction destination addresses.
        return rom_base.rom_base.disassemble(self, entries, create_labels,
                                             single_step, valid_range, breakpoints, vectors)
    

    def listing(self, source=False):
        """Produce listing in Intel format for 8-bit data, 16-bit address system.

        Keyword arguments:

        source   -- If True, output assembler soruce format. Otherwise,
                    output listing format with addres and data columns.
        """

        return rom_base.rom_base._listing_a16_d8_intel(self, source)


    def lookup_address(self, address, create_label=True, prefix='L_'):
        """Look up address in label map, returning symbol name or hex string.

        Keyword arguments:
        address      -- 16-bit address to look up.
        create_label -- If True, create label if not already defined.
        prefix       -- Prefix for automatically-created labels

        Returns:
        String containing either label name, or hexadecimal address in Intel
        assembler format."""

        return self._lookup_a16_intel(address, create_label, prefix)
    

    def lookup_port(self, port, create_label=True, prefix='P_'):
        """Look up port in IO port map, returning symbol name or hex string.

        Keyword arguments:
        port         -- 8-bit IO port number to look up
        create_label -- If True, create label if not already defined.
        prefix       -- Prefix for automatically-created labels

        Returns:
        String containing either port name, or hexadecimal address in Intel
        assembler format."""

        return self._lookup_port8(port, create_label, prefix)

