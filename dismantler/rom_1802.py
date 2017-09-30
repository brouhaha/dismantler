#!/usr/bin/env python
#
##########################################################################
# Copyright (C) 2017 Mark J. Blair, NF6X
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

"""Define class for ROM image containing RCA CDP1802 code to be disassembled."""

from . import rom_base
from . import util

# Default label map
default_labels = {0x0000:'RESET'}

# Default entry points
default_entries = [0x0000]

# There are no default port names
default_ports = {}

_op3x = ['BR',   'BQ',   'BZ',   'BDF',  'B1',   'B2',   'B3',   'B4',
         'SKP',  'BNQ',  'BNZ',  'BNF',  'BN1',  'BN2',  'BN3',  'BN4']

_op7x = ['RET',  'DIS',  'LDXA', 'STXD', 'ADC',  'SDB',  'SHRC', 'SMB',
         'SAV',  'MARK', 'SEQ',  'REQ',  'ADDI', 'SDBI', 'SHLC', 'SMBI']

_opCx = ['LBR',  'LBQ',  'LBZ',  'LBDF', 'NOP',  'LSNQ', 'LSNZ', 'LSNF',
         'LSKP', 'LBNQ', 'LBNZ', 'LBNF', 'LSIE', 'LSQ',  'LSZ',  'LSDF']

_opFx = ['LDX',  'OR',   'AND',  'XOR',  'ADD',  'SD',   'SHR',  'SM',
         'LDI',  'ORI',  'ANI',  'XRI',  'ADI',  'SDI',  'SHL',  'SMI']

class rom_1802(rom_base.rom_base):
    """ROM image containing RCA CDP1802 code to be disassembled."""


    description = 'RCA CDP1802 COSMAC'

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
        I = (opcode >> 4) & 0x0F
        N = opcode & 0x0F

        if I == 0x0:
            if N == 0x0:
                self.disassembly[idx] = 'IDL'
            else:
                self.disassembly[idx] = 'LDN  R{:X}'.format(N)
            next_addrs = [address + 1]

        elif I == 0x1:
            self.disassembly[idx] = 'INC  R{:X}'.format(N)
            next_addrs = [address + 1]

        elif I == 0x2:
            self.disassembly[idx] = 'DEC  R{:X}'.format(N)
            next_addrs = [address + 1]

        elif I == 0x3:
            # Branch target will be offset in same page as target operand
            page   = (address + 1) & 0xFF00
            offset = self.rom[idx + 1]
            target = page | offset

            if N == 0x0:
                # Unconditional branch
                self.disassembly[idx] = '{:4s} {:s}'.format(_op3x[N], self._lookup_a16_intel(target, create_label, 'J_'))
                self.data_type[idx+1] = rom_base.type_operand
                next_addrs = [target]
            elif N == 0x8:
                # Skip
                self.disassembly[idx] = _op3x[N]
                next_addrs = [address + 2]
            else:
                # Conditional branch
                self.disassembly[idx] = '{:4s} {:s}'.format(_op3x[N], self._lookup_a16_intel(target, create_label, 'J_'))
                self.data_type[idx+1] = rom_base.type_operand
                next_addrs = [address + 2, target]

        elif I == 0x4:
            self.disassembly[idx] = 'LDA  R{:X}'.format(N)
            next_addrs = [address + 1]

        elif I == 0x5:
            self.disassembly[idx] = 'STR  R{:X}'.format(N)
            next_addrs = [address + 1]

        elif I == 0x6:
            if N == 0x0:
                self.disassembly[idx] = 'IRX'
                next_addrs = [address + 1]
            elif N <= 0x7:
                self.disassembly[idx] = 'OUT  {:s}'.format(self._lookup_port8_intel(N, create_label))
                next_addrs = [address + 1]
            elif N == 0x8:
                self.data_type[idx]   = rom_base.type_error
                self.comments[idx]    += 'ERROR: Reserved Opcode '
                next_addrs = []
            else:
                self.disassembly[idx] = 'INP  {:s}'.format(self._lookup_port8_intel(N & 0x7, create_label))
                next_addrs = [address + 1]

        elif I == 0x7:
            if (N <= 0xB) or (N == 0xE):
                self.disassembly[idx] = _op7x[N]
                next_addrs = [address + 1]
            else:
                self.disassembly[idx] = '{:4s} {:s}'.format(_op7x[N], util.hex8_intel(self.rom[idx+1]))
                self.data_type[idx+1] = rom_base.type_operand
                next_addrs = [address + 2]

        elif I == 0x8:
            self.disassembly[idx] = 'GLO  R{:X}'.format(N)
            next_addrs = [address + 1]

        elif I == 0x9:
            self.disassembly[idx] = 'GHI  R{:X}'.format(N)
            next_addrs = [address + 1]

        elif I == 0xA:
            self.disassembly[idx] = 'PLO  R{:X}'.format(N)
            next_addrs = [address + 1]

        elif I == 0xB:
            self.disassembly[idx] = 'PHI  R{:X}'.format(N)
            next_addrs = [address + 1]

        elif I == 0xC:
            if N == 0:
                # Unconditional long branch
                self.data_type[idx+1] = rom_base.type_operand
                self.data_type[idx+2] = rom_base.type_operand
                target = (self.rom[idx+1] << 8) | self.rom[idx+2]
                self.disassembly[idx] = '{:4s} {:s}'.format(_opCx[N], self._lookup_a16_intel(target, create_label, 'J_'))
                next_addrs = [target]
            elif N <= 0x3:
                # Conditional long branch
                self.data_type[idx+1] = rom_base.type_operand
                self.data_type[idx+2] = rom_base.type_operand
                target = (self.rom[idx+1] << 8) | self.rom[idx+2]
                self.disassembly[idx] = '{:4s} {:s}'.format(_opCx[N], self._lookup_a16_intel(target, create_label, 'J_'))
                next_addrs = [address + 3, target]
            elif N == 0x4:
                # NOP
                self.disassembly[idx] = _opCx[N]
                next_addrs = [address + 1]
            elif N <= 0x7:
                # Conditional long skip
                self.disassembly[idx] = _opCx[N]
                next_addrs = [address + 3, address + 1]
            elif N == 0x8:
                # Unconditional long skip
                self.disassembly[idx] = _opCx[N]
                next_addrs = [address + 3]
            elif N <= 0xB:
                # Conditional long branch
                self.data_type[idx+1] = rom_base.type_operand
                self.data_type[idx+2] = rom_base.type_operand
                target = (self.rom[idx+1] << 8) | self.rom[idx+2]
                self.disassembly[idx] = '{:4s} {:s}'.format(_opCx[N], self._lookup_a16_intel(target, create_label, 'J_'))
                next_addrs = [address + 3, target]
            else:
                # Conditional long skip
                self.disassembly[idx] = _opCx[N]
                next_addrs = [address + 3, address + 1]

        elif I == 0xD:
            self.disassembly[idx] = 'SEP  R{:X}'.format(N)
            # Can't calculate next execution address without knowing
            # register contents
            next_addrs = []

        elif I == 0xE:
            self.disassembly[idx] = 'SEX  R{:X}'.format(N)
            next_addrs = [address + 1]

        elif I == 0xF:
            if (N <= 0x7) or (N == 0xE):
                self.disassembly[idx] = _opFx[N]
                next_addrs = [address + 1]
            else:
                self.disassembly[idx] = '{:4s} {:s}'.format(_opFx[N], util.hex8_intel(self.rom[idx + 1]))
                self.data_type[idx+1] = rom_base.type_operand
                next_addrs = [address + 2]

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

