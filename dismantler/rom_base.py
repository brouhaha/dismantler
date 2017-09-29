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

"""Define abstract base class for ROM image to be disassembled."""

from . import util

# Classifications of contents of a memory location:
# type_unknown:     Location has not yet been classified.
# type_instruction: Location contains first byte of instruction.
# type_operand:     Location contains second or later byte of instruction.
# type_data*:       Location contains data.
# type_vector*:     Location contains pointer to executable code.
# type_error:       Illegal opcode found at address.

type_unknown, type_instruction, type_operand, type_data8, \
  type_data16H, type_data16L, type_vector16H, type_vector16L, \
  type_error = list(range(9))

valid_types = [type_unknown, type_instruction, type_operand, type_data8,
               type_data16H, type_data16L, type_vector16H, type_vector16L,
               type_error]

data_types  = [type_data8, type_data16H, type_data16L, type_vector16H, type_vector16L]

type_names  = ['UNKNOWN', 'INSTRUCTION', 'OPERAND', 'DATA8',
               'DATA16H', 'DATA16L', 'VECTOR16H', 'VECTOR16L',
               'ERROR']

class rom_base(object):
    """Abstract base class for ROM image to be disassembled."""

    rom             = []  # ROM binary data
    rom_len         = 0   # Length of ROM
    base_address    = 0   # Base address of beginning of ROM
    max_address     = 0   # Address of last byte of ROM
    data_type       = []  # Data type classifications of each ROM byte
    disassembly     = []  # Disassembled for each instruction
    comments        = []  # Comments for each byte of ROM
    label_map       = {}  # Address label map
    port_map        = {}  # IO port label map
    special_labels  = {}  # Auto-generated label names for special addresses
    special_ports   = {}  # Auto-generated label names for special IO ports
    xref            = {}  # Call/branch/jump cross-reference
    vector_addrs    = []  # Addresses of all vectors
    vector_dests    = []  # Addresses of all vector destinations

    # Description of this processor:
    # Child classes must set this to a short string describing the processor.
    description = None

    def __init__(self, rom, base_address=0, label_map={}, port_map={}):
        """Object code item constructor.

        Keyword arguments:
        rom           -- Binary object code to be disassembled. Typically a bytearray.
        base_address  -- Memory address of first element of obj_code.
        label_map     -- Dictionary of label->address mappings.
        port_map      -- Dictionary of IO port name->address mappings (if applicable).
        """

        self.rom           = rom
        self.rom_len       = len(self.rom)
        self.base_address  = base_address
        self.max_address   = self.base_address + self.rom_len - 1
        self.data_type     = [type_unknown]*self.rom_len
        self.disassembly   = ['']*self.rom_len
        self.comments      = ['']*self.rom_len
        self.label_map     = label_map
        self.port_map      = port_map

    def _set_data8_intel(self, address, access_addr=None):
        """Classify location as 8-bit data, Intel format.

        Keyword arguments:
        address     -- Address of location to reclassify.
        access_addr -- Address of instruction which triggered this
                       classification. Used for warning comment
                       if change indicates probable disassembly error.
        """

        idx = address - self.base_address
        if (idx >= 0) and (idx < self.rom_len):
            if (self.data_type[idx] is not type_unknown) \
              and (self.data_type[idx] is not type_data8):
                if access_addr is None:
                    line = 'WARNING: Changed type {:s}->{:s}. '
                    line = line.format(type_names[self.data_type[idx]],
                                       type_names[type_data8])
                else:
                    line = 'WARNING: Access from {:s} changed type {:s}->{:s}. '
                    line = line.format(util.hex16_intel(access_addr),
                                       type_names[self.data_type[idx]],
                                       type_names[type_data8])
                self.comments[idx] += line 
            self.data_type[idx] = type_data8
            

    def _set_data16_le_intel(self, address, access_addr):
        """Classify location as 16-bit little-endian data, Intel format.

        Keyword arguments:
        address     -- Address of LSB location to reclassify.
        access_addr -- Address of instruction which triggered this
                       classification. Used for warning comment
                       if change indicates probable disassembly error.
        """

        idx = address - self.base_address
        if (idx >= 0) and (idx < self.rom_len):
            if (self.data_type[idx] is not type_unknown) \
              and (self.data_type[idx] is not type_data16L):
                if access_addr is None:
                    line = 'WARNING: Changed type {:s}->{:s}. '
                    line = line.format(type_names[self.data_type[idx]],
                                       type_names[type_data16L])
                else:
                    line = 'WARNING: Access from {:s} changed type {:s}->{:s}. '
                    line = line.format(util.hex16_intel(access_addr),
                                       type_names[self.data_type[idx]],
                                       type_names[type_data16L])
            self.data_type[idx] = type_data16L
        idx = idx + 1
        if (idx >= 0) and (idx < self.rom_len):
            if (self.data_type[idx] is not type_unknown) \
              and (self.data_type[idx] is not type_data16H):
                if access_addr is None:
                    line = 'WARNING: Changed type {:s}->{:s}. '
                    line = line.format(type_names[self.data_type[idx]],
                                       type_names[type_data16H])
                else:
                    line = 'WARNING: Access from {:s} changed type {:s}->{:s}. '
                    line = line.format(util.hex16_intel(access_addr),
                                       type_names[self.data_type[idx]],
                                       type_names[type_data16H])
            self.data_type[idx] = type_data16H
            
            

    def _set_vector16_le_intel(self, address, access_addr):
        """Classify location as 16-bit little-endian vector, Intel format.

        Keyword arguments:
        address     -- Address of LSB location to reclassify.
        access_addr -- Address of instruction which triggered this
                       classification. Used for warning comment
                       if change indicates probable disassembly error.
        Returns:
        Address contained at specified location.
        """

        idx = address - self.base_address
        vector = None
        if address not in self.vector_addrs:
            self.vector_addrs.append(address)
            
        if (idx >= 0) and (idx < self.rom_len):
            if (self.data_type[idx] is not type_unknown) \
              and (self.data_type[idx] is not type_vector16L):
                if access_addr is None:
                    line = 'WARNING: Changed type {:s}->{:s}. '
                    line = line.format(type_names[self.data_type[idx]],
                                       type_names[type_vector16L])
                else:
                    line = 'WARNING: Access from {:s} changed type {:s}->{:s}. '
                    line = line.format(util.hex16_intel(access_addr),
                                       type_names[self.data_type[idx]],
                                       type_names[type_vector16L])
            self.data_type[idx] = type_vector16L
            vector = self.rom[idx]
        idx = idx + 1
        if (idx >= 0) and (idx < self.rom_len):
            if (self.data_type[idx] is not type_unknown) \
              and (self.data_type[idx] is not type_vector16H):
                if access_addr is None:
                    line = 'WARNING: Changed type {:s}->{:s}. '
                    line = line.format(type_names[self.data_type[idx]],
                                       type_names[type_vector16H])
                else:
                    line = 'WARNING: Access from {:s} changed type {:s}->{:s}. '
                    line = line.format(util.hex16_intel(access_addr),
                                       type_names[self.data_type[idx]],
                                       type_names[type_vector16H])
            self.data_type[idx] = type_vector16H
            if vector is not None:
                vector = vector | (self.rom[idx] << 8)

        if vector is not None:
            if vector not in self.vector_dests:
                self.vector_dests.append(vector)
                
        return vector

            
            

    def set_data8(self, address, access_addr=None):
        """Classify location as 8-bit data.

        This virtual function must be defined in processor-specific classes,
        typically by calling the appropriate _set_data* member function.
        """

        raise NotImplementedError('Virtual function must be defined by inheritor.')

    def set_data16(self, address, access_addr=None):
        """Classify location as 16-bit data.

        This virtual function must be defined in processor-specific classes,
        typically by calling the appropriate _set_data* member function.
        """

        raise NotImplementedError('Virtual function must be defined by inheritor.')

    def set_vector(self, address, access_addr=None):
        """Classify location as containing a pointer to executable code and return contents.

        This virtual function must be defined in processor-specific classes,
        typically by calling the appropriate _set_data* member function.
        """

        raise NotImplementedError('Virtual function must be defined by inheritor.')

    def disasm_single(self, address, create_label=True):
        """Disassemble a single instruction.

        This virtual function must be defined in processor-specific classes.
        Responsibilities include:
        * Return [] if address has already been disassembled.
        * Set self.data_type for disassembled locations.
        * Set self.data_type for identified data addresses within ROM.
        * Disassemble the instruction. Set location to type_error and return []
          if instruction at address is invalid.
        * Return list of any computable addresses of next instruction to be executed.
          Typically begins with address following last operand byte, followed
          by branch address for conditional branch. May be [] for instructions
          which halt execution.
        """

        raise NotImplementedError('Virtual function must be defined by inheritor.')
    
        

    def disassemble(self, entries=[0], create_labels = True, single_step=False,
                    valid_range=None, breakpoints=[], vectors=[]):
        """Disassemble code, starting at specified entry point address(es).

        Keyword arguments:

        entries       -- List of entry point addresses at which to begin disassembly.
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

        if valid_range is not None:
            valid_min, valid_max = valid_range
        else:
            valid_min = self.base_address
            valid_max = self.max_address
            
        vecptrs = []
        for vector in vectors:
            ptr = self.set_vector(vector)
            vecptrs.append(ptr)
            if create_labels:
                self.lookup_address(ptr, True, 'V_')

        for entry in (entries + vecptrs):
            if (entry>=valid_min) and (entry<=valid_max) and (entry not in breakpoints):

                if (entry < self.base_address) or (entry > self.max_address):
                    raise IndexError('Disassembly address outside of valid range.')

                next_addr_list = self.disasm_single(entry, create_labels)
            
                if not single_step:
                    self.disassemble(next_addr_list, create_labels, False, (valid_min,valid_max), breakpoints)


    def _listing_a16_d8_intel(self, source=False):
        """Produce listing in Intel format for 8-bit data, 16-bit address system.

        Keyword arguments:

        source   -- If True, output assembler soruce format. Otherwise,
                    output listing format with addres and data columns.
        """
        
        listing_str = ''
        if source:
            indentation = ''
        else:
            indentation = ' '*24
        
        # Output any labels outside of ROM range
        listing_str = listing_str + '{:s}; External References:\n\n'.format(indentation)
        for address in sorted(self.label_map):
            if (address < self.base_address) or (address > self.max_address):
                line = '{:s}{:16s}  EQU  {:s}\n'
                line = line.format(indentation, self.label_map[address], util.hex16_intel(address))
                listing_str = listing_str + line 

        # Output the IO port map
        listing_str = listing_str + '\n{:s}; IO Port Map:\n\n'.format(indentation)
        for port in sorted(self.port_map):
            line = '{:s}{:16s}  EQU  {:s}\n'
            line = line.format(indentation, self.port_map[port], util.hex8_intel(port))
            listing_str = listing_str + line 
            
        # Begin code listing
        listing_str = listing_str + '\n{:s}; ROM Disassembly:\n\n'.format(indentation)
        address     = self.base_address
        idx         = 0
        previdx     = 0

        line = '\n{:s}                  ORG  {:s}\n\n'
        line = line.format(indentation, util.hex16_intel(self.base_address))
        listing_str = listing_str + line

        while address <= self.max_address:
            n = 1
            data_str = '{:02X}'.format(self.rom[idx])
            comment  = self.comments[idx]

            if address in self.label_map:
                label = self.label_map[address] + ':'
            else:
                label = ''
            
            if self.data_type[idx] is type_instruction:
                code_str = self.disassembly[idx]
                while ((idx + n) < len(self.data_type)) and self.data_type[idx + n] is type_operand:
                    data_str = data_str + ' {:02X}'.format(self.rom[idx + n])
                    if len(self.comments[idx + n]) > 0:
                        comment = comment + ' ' + self.comments[idx + n]
                    n = n + 1

            elif self.data_type[idx] is type_data8:
                code_str = 'DB   {:s}'.format(util.hex8_intel(self.rom[idx]))

            elif (self.data_type[idx] is type_data16L) and (self.data_type[idx+1] is type_data16H):
                word = self.rom[idx] | (self.rom[idx+1] << 8)
                code_str = 'DW   {:s}'.format(util.hex16_intel(word))
                comment = comment + ' ' + self.comments[idx + 1]
                n = n + 1

            elif (self.data_type[idx] is type_vector16L) and (self.data_type[idx+1] is type_vector16H):
                word = self.rom[idx] | (self.rom[idx+1] << 8)
                code_str = 'DW   {:s}'.format(self.lookup_address(word, False))
                comment = comment + ' ' + self.comments[idx + 1]
                n = n + 1

            elif (self.data_type[idx] is type_unknown):
                comment = '(UNREACHABLE) ' + comment
                code_str = 'DB   {:s}'.format(util.hex8_intel(self.rom[idx]))

            else:
                code_str = 'DB   {:s}'.format(util.hex8_intel(self.rom[idx]))

            if source:
                line = '{lbl:17s} {code:24s}; {comm:s}\n'
                line = line.format(lbl=label, code=code_str, comm=comment)
            else:
                line = '{addr:04X}  {dstr:16s}  {lbl:17s} {code:24s}; {comm:s}\n'
                line = line.format(addr=address, dstr=data_str, lbl=label, code=code_str, comm=comment)

            # Insert extra line breaks to improve readability
            if address in self.xref:
                # Line break before call/jump destinations
                line = '\n' + line
            elif address in self.vector_dests:
                # Line break before vector destinations
                line = '\n' + line
            elif (self.data_type[idx] is type_unknown) \
                and (self.data_type[previdx] is not type_unknown):
                # Line break before block of unreachable code
                line = '\n' + line
            elif (self.data_type[idx] is not type_unknown) \
                and (self.data_type[previdx] is type_unknown):
                # Line break after block of unreachable code
                line = '\n' + line
            elif (self.data_type[idx] in data_types) \
                and (self.data_type[previdx] not in data_types):
                # Line break before block of data
                line = '\n' + line
            elif (self.data_type[idx] not in data_types) \
                and (self.data_type[previdx] in data_types):
                # Line break after block of data
                line = '\n' + line

            listing_str = listing_str + line

            address = address + n
            previdx = idx
            idx     = idx + n

        listing_str = listing_str + '\n{:s}                  END\n\n'.format(indentation)

        # Output cross-reference
        if not source:
            listing_str = listing_str + '{:s}; Cross-Reference List:\n'.format(indentation)
            listing_str = listing_str + '{:s}; (Does not include calls via computed addresses or vectors)\n\n'.format(indentation)

            # Perform label substitution on destination addresses
            dest_list = {}
            for dest in list(self.xref.keys()):
                dest_list[self.lookup_address(dest, False)] = dest

            # Now sort by destination label/address strings
            for dest_str in sorted(dest_list.keys()):
                dest = dest_list[dest_str]
                # Perform label substitution on source addresses
                source_list = []
                for source in self.xref[dest]:
                    source_list.append(self.lookup_address(source, False))
                # Print the cross-reference for this destination
                listing_str = listing_str + '{:s}; {:17s}'.format(indentation, dest_str+':')
                for source_str in sorted(source_list):
                    listing_str = listing_str + ' {:s}'.format(source_str)
                listing_str = listing_str + '\n'

        return listing_str


    def listing(self, source=False):
        """Return listing of ROM.

        This virtual function must be defined in processor-specific classes.
        Implementation may be as simple as calling one of the _listing* members functions.
        """

        raise NotImplementedError('Virtual function must be defined by inheritor.')
    
    def _lookup_a16_intel(self, address, create_label=True, prefix='L_'):
        """Look up address in label map, returning symbol name or hex string.

        Keyword arguments:
        address      -- 16-bit address to look up.
        create_label -- If True, create label if not already defined.
        prefix       -- Prefix for automatically-created labels

        Returns:
        String containing either label name, or hexadecimal address in Intel
        assembler format."""

        if address in self.label_map:
            return self.label_map[address]
        elif create_label:
            if address in self.special_labels:
                label = self.special_labels[address]
            else:
                label = '{:s}{:04X}'.format(prefix, address)
            self.label_map[address] = label
            return label
        else:
            return util.hex16_intel(address)
        
    def _lookup_port8_intel(self, port, create_label=True, prefix='P_'):
        """Look up port in IO port map, returning symbol name or hex string.

        Keyword arguments:
        port         -- 8-bit IO port number to look up
        create_label -- If True, create label if not already defined.
        prefix       -- Prefix for automatically-created labels

        Returns:
        String containing either port name, or hexadecimal address in Intel
        assembler format."""

        if port in self.port_map:
            return self.port_map[port]
        elif create_label:
            if port in self.special_ports:
                label = self.special_ports[port]
            else:
                label = '{:s}{:02X}'.format(prefix, port)
            self.port_map[port] = label
            return label
        else:
            return util.hex8_intel(port)
        

    def lookup_address(self, address, create_label=True, prefix='L_'):
        """Look up address in label map, returning symbol name or hex string.

        This virtual function must be defined in processor-specific classes,
        typically by calling the appropriate _lookup_a* member function.
        """

        raise NotImplementedError('Virtual function must be defined by inheritor.')


    def lookup_port(self, address, create_label=True, prefix='L_'):
        """Look up port in IO port map, returning symbol name or hex string.

        This virtual function must be defined in processor-specific classes,
        typically by calling the appropriate _lookup_port* member function.
        """

        raise NotImplementedError('Virtual function must be defined by inheritor.')


    def add_xref(self, source, dest):
        """Add call/jump/branch to cross-reference dictionary.

        Keyword arguments:
        source -- Address of calling instruction.
        dest   -- Address of called function."""

        if dest in self.xref:
            if dest not in self.xref[dest]:
                self.xref[dest].append(source)
        else:
            self.xref[dest] = [source]
    

