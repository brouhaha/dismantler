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

"""Define class for ROM image containing Intel z80 code to be disassembled."""

import rom_base
import util
import exceptions

_alu = ['ADD  A, ', 'ADC  A, ', 'SUB  ', 'SBC  A, ', 'AND  ', 'XOR  ', 'OR   ', 'CP   ']
_bli = [['LDI',  'CPI',  'INI',  'OUTI'],
        ['LDD',  'CPD',  'IND',  'OUTD'],
        ['LDIR', 'CPIR', 'INIR', 'OTIR'],
        ['LDDR', 'CPDR', 'INDR', 'OTDR']]
_cc  = ['NZ', 'Z', 'NC', 'C', 'PO', 'PE', 'P', 'M']
_im  = ['0', '0/1', '1', '2', '0', '0/1', '1', '2']
_r   = ['B', 'C', 'D', 'E', 'H', 'L', '(HL)', 'A']
_rot = ['RLC', 'RRC', 'RL', 'RR', 'SLA', 'SRA', 'SLL', 'SRL']
_rp  = ['BC', 'DE', 'HL', 'SP']
_rp2 = ['BC', 'DE', 'HL', 'AF']

# Default label map
default_labels = {0x0000:'RST00', 0x0008:'RST08', 0x0010:'RST10', 0x0018:'RST18',
                  0x0020:'RST20', 0x0028:'RST28', 0x0030:'RST30', 0x0038:'RST38',
                  0x0066:'NMI'}

# Default entry points
default_entries = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x66]

# There are no default port names
default_ports = {}

class rom_z80(rom_base.rom_base):
    """ROM image containing Zilog z80 code to be disassembled."""


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
                elif y == 1:
                    self.disassembly[idx] = 'EX   AF, AF\''
                    next_addrs = [address + 1]
                elif y == 2:
                    dest = address + util.signed_byte(self.rom[idx+1])
                    self.data_type[idx+1] = rom_base.type_operand
                    self.disassembly[idx] = 'DJNZ {:s}'.format(self.lookup_a16_intel(dest, create_label, 'J_'))
                    next_addrs = [address + 2, dest]
                elif y == 3:
                    dest = address + util.signed_byte(self.rom[idx+1])
                    self.data_type[idx+1] = rom_base.type_operand
                    self.disassembly[idx] = 'JR   {:s}'.format(self.lookup_a16_intel(dest, create_label, 'J_'))
                    next_addrs = [dest]
                else:
                    dest = address + util.signed_byte(self.rom[idx+1])
                    self.data_type[idx+1] = rom_base.type_operand
                    self.disassembly[idx] = 'JR   {:s}, {:s}'.format(_cc[y-4], self.lookup_a16_intel(dest, create_label, 'J_'))
                    next_addrs = [address + 2, dest]
                    
            elif z == 1:
                # 16-bit load immediate/add
                if q == 0:
                    word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                    self.data_type[idx+1] = rom_base.type_operand
                    self.data_type[idx+2] = rom_base.type_operand
                    self.disassembly[idx] = 'LD   {:s}, {:s}'.format(_rp[p], util.hex16_intel(word))
                    next_addrs = [address + 3]
                else:
                    self.disassembly[idx] = 'ADD  HL, {:s}'.format(_rp[p])
                    next_addrs = [address + 1]
            elif z == 2:
                # Indirect loading
                if q == 0:
                    if p <= 1:
                        self.disassembly[idx] = 'LD   ({:s}), A'.format(_rp[p])
                        next_addrs = [address + 1]
                    elif p == 2:
                        word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                        self.data_type[idx+1] = rom_base.type_operand
                        self.data_type[idx+2] = rom_base.type_operand
                        self.disassembly[idx] = 'LD   ({:s}), HL'.format(self.lookup_a16_intel(word, create_label, 'D_'))
                        self.set_data16(word, address)
                        next_addrs = [address + 3]
                    else:
                        word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                        self.data_type[idx+1] = rom_base.type_operand
                        self.data_type[idx+2] = rom_base.type_operand
                        self.disassembly[idx] = 'LD   ({:s}), A'.format(self.lookup_a16_intel(word, create_label, 'D_'))
                        self.set_data8(word, address)
                        next_addrs = [address + 3]
                else:
                    if p <= 1:
                        self.disassembly[idx] = 'LD   A, ({:s})'.format(_rp[p])
                        next_addrs = [address + 1]
                    elif p == 2:
                        word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                        self.data_type[idx+1] = rom_base.type_operand
                        self.data_type[idx+2] = rom_base.type_operand
                        self.disassembly[idx] = 'LD   HL, ({:s})'.format(self.lookup_a16_intel(word, create_label, 'D_'))
                        self.set_data16(word, address)
                        next_addrs = [address + 3]
                    else:
                        word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                        self.data_type[idx+1] = rom_base.type_operand
                        self.data_type[idx+2] = rom_base.type_operand
                        self.disassembly[idx] = 'LD   A, ({:s})'.format(self.lookup_a16_intel(word, create_label, 'D_'))
                        self.set_data8(word, address)
                        next_addrs = [address + 3]

            elif z == 3:
                #16-bit INC/DEC
                if q == 0:
                    self.disassembly[idx] = 'INC  {:s}'.format(_rp[p])
                else:
                    self.disassembly[idx] = 'DEC  {:s}'.format(_rp[p])
                next_addrs = [address + 1]

            elif z == 4:
                # 8-bit INC
                self.disassembly[idx] = 'INC  {:s}'.format(_r[y])
                next_addrs = [address + 1]

            elif z == 5:
                # 8-bit DEC
                self.disassembly[idx] = 'DEC  {:s}'.format(_r[y])
                next_addrs = [address + 1]

            elif z == 6:
                # 8-bit load immediate
                self.data_type[idx+1] = rom_base.type_operand
                self.disassembly[idx] = 'LD   {:s}, {:s}'.format(_r[y], util.hex8_intel(self.rom[idx+1]))
                next_addrs = [address + 2]

            elif z == 7:
                # Assorted operations on accumulator/flags
                if y == 0:
                    self.disassembly[idx] = 'RLCA'
                elif y == 1:
                    self.disassembly[idx] = 'RRCA'
                elif y == 2:
                    self.disassembly[idx] = 'RLA'
                elif y == 3:
                    self.disassembly[idx] = 'RRA'
                elif y == 4:
                    self.disassembly[idx] = 'DAA'
                elif y == 5:
                    self.disassembly[idx] = 'CPL'
                elif y == 6:
                    self.disassembly[idx] = 'SCF'
                else:
                    self.disassembly[idx] = 'CCF'
                next_addrs = [address + 1]

        elif x == 1:
            if (z == 6) and (y == 6):
                # Exception
                self.disassembly[idx] = 'HALT'
            else:
                self.disassembly[idx] = 'LD   {:s}, {:s}'.format(_r[y],_r[z])
            next_addrs = [address + 1]

        elif x == 2:
            # Operate on accumulator and register/memory location
            self.disassembly[idx] = '{:s}{:s}'.format(_alu[y],_r[z])
            next_addrs = [address + 1]

        elif x == 3:

            if z == 0:
                # Conditional return
                self.disassembly[idx] = 'RET  {:s}'.format(_cc[y])
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
                        self.disassembly[idx] = 'EXX'
                        next_addrs = [address + 1]
                    elif p == 2:
                        self.disassembly[idx] = 'JP   HL'
                        next_addrs = []
                    else:
                        self.disassembly[idx] = 'LD   SP, HL'
                        next_addrs = [address + 1]

            elif z == 2:
                # Conditional jump
                word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                self.data_type[idx+1] = rom_base.type_operand
                self.data_type[idx+2] = rom_base.type_operand
                self.disassembly[idx] = 'JP   {:s}, {:s}'.format(_cc[y], self.lookup_a16_intel(word, create_label, 'J_'))
                next_addrs = [address + 3, word]

            elif z == 3:
                # Assorted operations
                if y == 0:
                    word = self.rom[idx+1] | (self.rom[idx+2] << 8)
                    self.data_type[idx+1] = rom_base.type_operand
                    self.data_type[idx+2] = rom_base.type_operand
                    self.disassembly[idx] = 'JP   {:s}'.format(self.lookup_a16_intel(word, create_label, 'J_'))
                    next_addrs = [word]
                elif y == 1:
                    # CB prefix
                    opcode2 = self.rom[idx+1]
                    x2 = (opcode2 >> 6) & 0x03
                    y2 = (opcode2 >> 3) & 0x07
                    z2 = opcode2 & 0x07
                    p2 = (y2 >> 1)
                    q2 = y2 & 0x01
                    self.data_type[idx+1] = rom_base.type_operand

                    if x2 == 0:
                        self.disassembly[idx] = '{:4s} {:s}'.format(_rot[y2], _r[z2])
                    elif x2 == 1:
                        self.disassembly[idx] = 'BIT  {:d}, {:s}'.format(y, _r[z2])
                    elif x2 == 2:
                        self.disassembly[idx] = 'RES  {:d}, {:s}'.format(y, _r[z2])
                    else:
                        self.disassembly[idx] = 'SET  {:d}, {:s}'.format(y, _r[z2])

                    next_addrs = [address + 2]

                elif y == 2:
                    self.data_type[idx+1] = rom_base.type_operand
                    self.disassembly[idx] = 'OUT  ({:s}), A'.format(self.lookup_port8_intel(self.rom[idx+1], create_label))
                    next_addrs = [address+2]
                elif y == 3:
                    self.data_type[idx+1] = rom_base.type_operand
                    self.disassembly[idx] = 'IN   A, ({:s})'.format(self.lookup_port8_intel(self.rom[idx+1], create_label))
                    next_addrs = [address+2]
                elif y == 4:
                    self.disassembly[idx] = 'EX   (SP), HL'
                    next_addrs = [address+1]
                elif y == 5:
                    self.disassembly[idx] = 'EX   DE, HL'
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
                self.disassembly[idx] = 'CALL {:s}, {:s}'.format(_cc[y], self.lookup_a16_intel(word, create_label, 'C_'))
                next_addrs = [address + 3, word]

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
                        self.disassembly[idx] = 'CALL {:s}'.format(self.lookup_a16_intel(word, create_label, 'C_'))
                        next_addrs = [address + 3, word]
                    elif p == 1:
                    # DD prefix
                        raise exceptions.NotImplementedError, 'DD prefixed instructions not implemented yet.'
################################

                    elif p == 2:
                        # ED prefix
                        opcode2 = self.rom[idx+1]
                        x2 = (opcode2 >> 6) & 0x03
                        y2 = (opcode2 >> 3) & 0x07
                        z2 = opcode2 & 0x07
                        p2 = (y2 >> 1)
                        q2 = y2 & 0x01
                        self.data_type[idx+1] = rom_base.type_operand

                        if (x2 == 0) or (x2 == 3):
                            self.comments[idx] += 'ERROR: invalid opcode ED{:s} '.format(util.hex8_intel(opcode2))
                            self.comments[idx+1] = self.comments[idx]
                            self.data_type[idx] = rom_base.type_error
                            self.data_type[idx+1] = rom_base.type_error
                            next_addrs = [address + 2]

                        elif x2 == 1:
                            if z2 == 0:
                                # Input from port with 16 bit address
                                if y2 == 6:
                                    self.disassembly[idx] = 'IN   (C)'
                                else:
                                    self.disassembly[idx] = 'IN   {:s}, (C)'.format(_r[y2])
                                next_addrs = [address + 2]
                            elif z2 == 1:
                                # Output to port with 16 bit address
                                if y2 == 6:
                                    self.disassembly[idx] = 'OUT  (C), 0'
                                else:
                                    self.disassembly[idx] = 'OUT  (C), {:s}'.format(_r[y2])
                                next_addrs = [address + 2]
                            elif z2 == 2:
                                # 16-but add/subtract with carry
                                if q2 == 0:
                                    self.disassembly[idx] = 'SBC  HL, {:s}'.format(_rp[p2])
                                else:
                                    self.disassembly[idx] = 'ADC  HL, {:s}'.format(_rp[p2])
                                next_addrs = [address + 2]
                            elif z2 == 3:
                                # Load/store register pair from/to immeidate address
                                word = self.rom[idx+2] | (self.rom[idx+3] << 8)
                                self.data_type[idx+2] = rom_base.type_operand
                                self.data_type[idx+3] = rom_base.type_operand
                                self.set_data16(word, address)

                                if q2 == 0:
                                    self.disassembly[idx] = 'LD   ({:s}), {:s}'.format(self.lookup_a16_intel(word, create_label, 'D_'), _rp[p2])
                                else:
                                    self.disassembly[idx] = 'LD   {:s}, ({:s})'.format(_rp[p2], self.lookup_a16_intel(word, create_label, 'D_'))
                                next_addrs = [address + 4]
                            elif z2 == 4:
                                # Negate accumulator
                                self.disassembly[idx] = 'NEG'
                                next_addrs = [address + 2]
                            elif z2 == 5:
                                # Return from interrupt
                                if y == 1:
                                    self.disassembly[idx] = 'RETI'
                                else:
                                    self.disassembly[idx] = 'RETN'
                                next_addrs = []
                            elif z2 == 6:
                                # Set interrupt mode
                                self.disassembly[idx] = 'IM   {:s}'.format(_im[y2])
                            else:
                                # Assorted ops
                                if y2 == 0:
                                    self.disassembly[idx] = 'LD   I, A'
                                elif y2 == 1:
                                    self.disassembly[idx] = 'LD   R, A'
                                elif y2 == 2:
                                    self.disassembly[idx] = 'LD   A, I'
                                elif y2 == 3:
                                    self.disassembly[idx] = 'LD   A, R'
                                elif y2 == 4:
                                    self.disassembly[idx] = 'RRD'
                                elif y2 == 5:
                                    self.disassembly[idx] = 'RLD'
                                else:
                                    self.disassembly[idx] = 'NOP'
                                next_addrs = [address + 2]
                        else:
                            # x2 == 2
                            if (z2 <= 3) and (y2 >= 4):
                                # Block instructions
                                self.disassembly[idx] = _bli[y2-4, z2]
                            else:
                                self.comments[idx] += 'ERROR: invalid opcode ED{:s} '.format(util.hex8_intel(opcode2))
                                self.comments[idx+1] = self.comments[idx]
                                self.data_type[idx] = rom_base.type_error
                                self.data_type[idx+1] = rom_base.type_error
                                next_addrs = [address + 2]

                    else:
                    # FD prefix
                        raise exceptions.NotImplementedError, 'FD prefixed instructions not implemented yet.'
################################

            elif z == 6:
                # Operate on accumulator and immediate operand
                self.data_type[idx+1] = rom_base.type_operand
                self.disassembly[idx] = '{:s}{:s}'.format(_alu[y],util.hex8_intel(self.rom[idx+1]))
                next_addrs = [address + 2]
                pass
            elif z == 7:
                # Restart
                self.disassembly[idx] = 'RST  {:d}'.format(y*8)
                next_addrs = [y*8]

        return next_addrs


    def disassemble(self, entries=default_entries,
                    create_labels = True, single_step=False, valid_range=None, breakpoints=[]):
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
        """

        # We are just changing the default entries argument value here, to default
        # to the RST intruction destination addresses.
        return rom_base.rom_base.disassemble(self, entries, create_labels,
                                             single_step, valid_range, breakpoints)
    

    def listing(self, source=False):
        """Produce listing in Intel format for 8-bit data, 16-bit address system.

        Keyword arguments:

        source   -- If True, output assembler soruce format. Otherwise,
                    output listing format with addres and data columns.
        """

        return rom_base.rom_base._listing_a16_d8_intel(self, source)
