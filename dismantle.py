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

"""dismantle.py: Disassemble a binary ROM image file.
"""

import sys
import argparse
import textwrap

import dismantler

def parse_int(x):
    """Parse argument and return integer value, performing base conversion if needed."""
    return int(x,0)

class parse_label_def(argparse.Action):
    """Parse memory label definition."""
    def __call__(self, parser, args, values, option_string=None):
        address, label  = (parse_int(values[0]), values[1])
        if args.labels is None:
            args.labels = {}
        args.labels[address] = label
        
class parse_port_def(argparse.Action):
    """Parse port label definition."""
    def __call__(self, parser, args, values, option_string=None):
        port, label  = (parse_int(values[0]), values[1])
        if args.ports is None:
            args.ports = {}
        args.ports[port] = label

# Main entry point when called as an executable script.
if __name__ == '__main__':

    # Create command line argument parser.
    parser = argparse.ArgumentParser(
        prog='dismantle.py',
        description=textwrap.dedent("""\
        Extensible disassembler with semiautomatic code identification, version {:s}
          {:s}
          {:s}
          {:s}""".format(dismantler.__version__, dismantler.__copyright__,
                         dismantler.__pkg_url__, dismantler.__dl_url__)),
        epilog=textwrap.dedent("""\
        Example:
          dismantle.py -c 8085 -a rom.bin
        """),
        add_help=True,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    # Define valid command line arguments
    parser.add_argument('--list_cpus', action='store_true',
                        help='List supported CPU types and exit.')

    parser.add_argument('-c', '--cpu', action='store',
                        metavar='CPU',
                        choices=dismantler.cpus,
                        help='(REQUIRED) Specify CPU type.')

    parser.add_argument('-B', '--base_address', action='store', type=parse_int, default=0,
                        metavar='ADDRESS',
                        help='Specify base address of ROM image. Default = 0x0000.')

    parser.add_argument('-e', '--entry', action='append', type=parse_int,
                        metavar='ADDRESS', dest='entries',
                        help="""Specify an entry point for disassembly.
                                Flag may be used multiple times.
                                Default varies by CPU type.""")

    parser.add_argument('-b', '--breakpoint', action='append', type=parse_int,
                        metavar='ADDRESS', dest='breakpoints',
                        help="""Specify breakpoints at which disassembly stops.
                                Flag may be used multiple times.""")

    parser.add_argument('-a', '--auto_label', action='store_true',
                        help='Automatically create labels for probable jumps, calls and variables.')
    
    parser.add_argument('-l', '--label', action=parse_label_def, nargs=2, dest='labels',
                        metavar=('ADDRESS', 'LABEL'),
                        help="""Define a memory address label.
                                Flag may be used multiple times.
                                If no labels are defined, default labels vary by CPU type.""")
    
    parser.add_argument('-p', '--port', action=parse_port_def, nargs=2, dest='ports',
                        metavar=('PORTNUM', 'LABEL'),
                        help="""Define an IO port label.
                                Flag may be used multiple times.
                                Only applicable to CPUs with a separate IO space.
                                If no labels are defined, default labels vary by CPU type.""")

    parser.add_argument('-d', '--data8', action='append', type=parse_int,
                        metavar='ADDRESS',
                        help='Classify location as 8-bit data prior to disassembly.')

    parser.add_argument('-w', '--data16', action='append', type=parse_int,
                        metavar='ADDRESS',
                        help='Classify location as 16-bit data prior to disassembly.')

    parser.add_argument('-v', '--vector', action='append', type=parse_int,
                        metavar='ADDRESS', dest='vectors',
                        help="""Classify location as a vector pointing to executable code.
                                Contents of location are added to entry list, and are subject
                                to label substitution and creation.""")

    parser.add_argument('-s', '--source', action='store_true',
                        help='Output assembler source format instead of listing format.')

    parser.add_argument('bin_file', action='store', type=argparse.FileType('rb'),
                        nargs='?', default=None,
                        help='Binary file containing image of ROM to be disassembled.')

    def arg_error(msg):
        """Print error message, print usage summary, and exit with error code."""
        print('ERROR: {:s}\n'.format(msg))
        parser.print_usage()
        exit(1)

    # Parse command line arguments
    args = parser.parse_args()

    # List CPUs and exit if --list_cpus is specified
    if (args.list_cpus == 1):
        print('Supported CPUs:')
        for cpu in sorted(list(dismantler.cpus.keys())):
            print('  {:8} {:}'.format(cpu, dismantler.cpus[cpu].description))
        exit(0)

    # Make sure necessary arguments are present
    if args.bin_file is None:
        arg_error('You need to specify a binary file to be disassembled.')
    if args.cpu is None:
        arg_error('You need to specify the CPU type with the -c/--cpu flag.')

    # Use default label map if auto label mode is requested
    # and there are no user-provided labels.
    if args.auto_label and (args.labels is None):
        labels = dismantler.default_labels[args.cpu]
    else:
        labels = {}
    if args.labels is not None:
        for address in args.labels:
            labels[address] = args.labels[address]

    # Use default port map if auto label mode is requested
    # and there are no user-provided ports.
    if args.auto_label and (args.ports is None):
        ports = dismantler.default_ports[args.cpu]
    else:
        ports = {}
    if args.ports is not None:
        for port in args.ports:
            ports[port] = args.ports[port]
            
    # Use default entry list for CPU if no entries are specified
    if args.entries is None:
        entries = dismantler.default_entries[args.cpu]
    else:
        entries=args.entries

    if args.breakpoints is not None:
        breakpoints = args.breakpoints
    else:
        breakpoints = []

    if args.vectors is not None:
        vectors = args.vectors
    else:
        vectors = []

    # Read the binary ROM image
    rom_data = bytearray(args.bin_file.read())
    args.bin_file.close()

    # Prepare the ROM image
    rom = dismantler.cpus[args.cpu](rom=rom_data,
                                    base_address=args.base_address,
                                    label_map=labels,
                                    port_map=ports)



    # Classify data locations
    if args.data8 is not None:
        for address in args.data8:
            rom.set_data8(address)

    if args.data16 is not None:
        for address in args.data16:
            rom.set_data16(address)

    # Disassemble the ROM image
    rom.disassemble(entries=entries,
                    create_labels=args.auto_label,
                    breakpoints=breakpoints,
                    vectors=vectors)

    # Generate and output the listing
    sys.stdout.write(rom.listing(source=args.source))

    # Done!
    exit(0)

