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
default_labels = {0x0000: 'RESET'}

# Default entry points
default_entries = [0x0000]

# There are no default port names
default_ports = {}

class rom_1802(rom_base.rom_base):
    """ROM image containing RCA CDP1802 code to be disassembled."""


    description = 'RCA CDP1802 COSMAC (NOT IMPLEMENTED YET)'

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

