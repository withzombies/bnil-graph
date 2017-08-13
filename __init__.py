#!/usr/bin/env python
# Copyright 2017 Ryan Stortz (@withzombies)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
from binaryninja import *
from collections import defaultdict
import subprocess
import tempfile

# Show normal form instructions (non-SSA, non-mapped) in the output
show_normal = True

# Included MappedMediumLevelIL in the output
show_mapped = False

# Include SSA in the output
show_ssa = True

# Path to dot executable
dot = '/usr/local/bin/dot'

dotfile = None

def print_il_graphviz(name, il):
    if isinstance(il, MediumLevelILInstruction) or isinstance(il, LowLevelILInstruction):
        dotfile.write('{} [label="{}", style="rounded"];\n'.format(name, il.operation.name))

        for i, o in enumerate(il.operands):
            edge_label = il.ILOperations[il.operation][i][0]
            child_name = "{}_{}".format(name, i)
            print_il_graphviz(child_name, o)

            # print edge
            dotfile.write('{} -> {} [label="  {}"];\n'.format(name, child_name, edge_label))
    elif isinstance(il, list):
        dotfile.write('{} [label="[{}]", shape="diamond"];'.format(name, len(il)))
        for i, item in enumerate(il):
            item_name = "{}_{}".format(name, i)
            print_il_graphviz(item_name, item)
            dotfile.write('{} -> {} [label="  {}"];'.format(name, item_name, i))
    else:
        # terminal
        if isinstance(il, long):
            (signed, ) = struct.unpack("l", struct.pack("L", il))
            il_str = "{: d} ({:#x})".format(signed, il)
        else:
            il_str = str(il)
        dotfile.write('{} [label="{}", shape="oval"];\n'.format(name, il_str))

def graph_il(il_type, il):
    # type: (LowLevelILInstruction) -> None

    h = hash(il)
    name = "g_{}_{}".format(h, il.address)
    child_name = "{}c".format(name)

    # print head
    il_str = str(il).replace("{", "\\{").replace("}", "\\}").replace(">", "\\>").replace("<", "\\<")
    dotfile.write('{} [label="{{ {} | {} @ {:#x} | {} }}", shape="record"];\n'.format(name, il_type, il.instr_index,
                                                                                      il.address, il_str))
    print_il_graphviz(child_name, il)

    #print edge
    dotfile.write('{} -> {};\n'.format(name, child_name))


def graph_addr(func, addr):
    lookup = defaultdict(lambda: defaultdict(list))

    llil = func.low_level_il
    mlil = func.medium_level_il

    if show_normal:
        for block in llil:
            for il in block:
                lookup['LowLevelIL'][il.address].append(il)

        for block in mlil:
            for mil in block:
                lookup['MediumLevelIL'][mil.address].append(mil)

    if show_ssa:
        for block in llil.ssa_form:
            for il in block:
                lookup['LowLevelILSSA'][il.address].append(il)

        for block in mlil.ssa_form:
            for mil in block:
                lookup['MediumLevelILSSA'][mil.address].append(mil)

    if show_mapped:
        mmlil = llil.mapped_medium_level_il
        for block in mmlil:
            for mil in block:
                lookup['MappedMediumLevelIL'][mil.address].append(mil)

        if show_ssa:
            for block in mmlil.ssa_form:
                for mil in block:
                    lookup['MappedMediumLevelILSSA'][mil.address].append(mil)

    dotfile.write("digraph G {\n")
    dotfile.write('node [shape="rect"];\n')
    for il_type in sorted(lookup):
        ils = lookup[il_type][addr]
        for il in sorted(ils):
            graph_il(il_type, il)
    dotfile.write("}\n")

def graph_bnil(bv, addr):
    global dotfile
    dotfile = tempfile.NamedTemporaryFile(mode="w", suffix=".dot")
    blocks = bv.get_basic_blocks_at(addr)
    func = blocks[0].function
    graph_addr(func, addr)
    dotfile.flush()

    subprocess.check_call([dot, '-Tpng', '-O', dotfile.name])
    bv.show_html_report("BNIL Graph", "<html><img src='{}.png'></html>".format(dotfile.name))

PluginCommand.register_for_address("BNIL Instruction Graph", "View BNIL Instruction Information", graph_bnil)
