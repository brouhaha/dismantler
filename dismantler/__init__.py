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

"""Python binding for the hidapi library."""

__all__       = ['rom_base', 'util', 'rom_1802', 'rom_8080', 'rom_8085', 'rom_z80']
__version__   = '0.3.0'
__copyright__ = 'Copyright (C) 2015, 2017 Mark J. Blair, released under GPLv3'
__pkg_url__   = 'http://www.nf6x.net/tags/dismantler/'
__dl_url__    = 'https://github.com/NF6X/dismantler'

from dismantler import *
import sys

# This program uses deep recursion. Whether that is good or
# bad is open for debate, but as currently implemented, the
# default recursion limit may be too small.
#
# Increase the recursion limit for now, and consider changing
# implementation to avoid recursion later.
#
_recursionlimit = 65536
if sys.getrecursionlimit() < _recursionlimit:
    sys.setrecursionlimit(_recursionlimit)

# You can use the following dictionary to create a new object
# derived from rom_base, given a CPU type string, like this example:
#   import dismantler
#   rom = dismantler.cpus['8085'](rom=mybuffer, base_address=0x0000,
#                                 label_map={0x0000:'RESET'},
#                                 port_map={0xF0:'UART0', 0xF8:'UART1'})
cpus = {'1802': rom_1802.rom_1802,
        '8080': rom_8080.rom_8080,
        '8085': rom_8085.rom_8085,
        'z80':  rom_z80.rom_z80}

# Similarly, these maps provide the default label maps and entry points
# for each CPU type:
default_labels = {'1802': rom_1802.default_labels,
                  '8080': rom_8080.default_labels,
                  '8085': rom_8085.default_labels,
                  'z80':  rom_z80.default_labels}

default_entries = {'1802': rom_1802.default_entries,
                   '8080': rom_8080.default_entries,
                   '8085': rom_8085.default_entries,
                   'z80':  rom_z80.default_entries}

default_ports = {'1802': rom_1802.default_ports,
                 '8080': rom_8080.default_ports,
                 '8085': rom_8085.default_ports,
                 'z80':  rom_z80.default_ports}

    
