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

# Show normal form instructions (non-SSA, non-mapped) in the output
show_normal = True

# Included MappedMediumLevelIL in the output
show_mapped = False

# Include SSA in the output
show_ssa = True


def graph_il_insn(g, head, il, label=None):
    # type: (FlowGraph, FlowGraphNode, LowLevelILInstruction, Optional[str]) -> None

    record = FlowGraphNode(g)
    tokens = []

    if label:
        tokens.extend(
            [
                InstructionTextToken(
                    InstructionTextTokenType.KeywordToken, "{}".format(label)
                ),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, ": "
                ),
            ]
        )

    if isinstance(il, MediumLevelILInstruction) or isinstance(
        il, LowLevelILInstruction
    ):

        tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.InstructionToken, il.operation.name
            )
        )

        for i, o in enumerate(il.operands):
            edge_label = il.ILOperations[il.operation][i][0]
            graph_il_insn(g, record, o, edge_label)
    elif isinstance(il, list):
        tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.IntegerToken, "List[{}]".format(len(il))
            )
        )

        for i, item in enumerate(il):
            edge_label = "[{:d}]".format(i)
            graph_il_insn(g, record, item, edge_label)

    else:
        if isinstance(il, long):
            tokens.append(
                InstructionTextToken(
                    InstructionTextTokenType.IntegerToken, "{:x}".format(il), value=il
                )
            )
        else:
            tokens.append(
                InstructionTextToken(InstructionTextTokenType.TextToken, str(il))
            )

    record.lines = [DisassemblyTextLine(tokens)]
    g.append(record)
    head.add_outgoing_edge(BranchType.UnconditionalBranch, record)


def graph_il(g, head, type, il):
    # type: (FlowGraph, FlowGraphNode, str, LowLevelILInstruction) -> None

    il_desc = binaryninja.FlowGraphNode(g)

    il_desc.lines = [
        "{}".format(type),
        "",
        DisassemblyTextLine(
            [
                InstructionTextToken(
                    InstructionTextTokenType.AddressDisplayToken,
                    "{:#x}".format(il.instr_index),
                    value=il.instr_index,
                ),
                InstructionTextToken(
                    InstructionTextTokenType.OperandSeparatorToken, " @ "
                ),
                InstructionTextToken(
                    InstructionTextTokenType.AddressDisplayToken,
                    "{:#x}".format(il.address),
                    value=il.address,
                ),
            ]
        ),
        il.tokens,
    ]

    graph_il_insn(g, il_desc, il, "operation")
    g.append(il_desc)

    head.add_outgoing_edge(BranchType.UnconditionalBranch, il_desc)


def graph_ils(bv, g, head, func, addr):
    lookup = defaultdict(lambda: defaultdict(list))

    llil = func.low_level_il
    mlil = func.medium_level_il

    if show_normal:
        for block in llil:
            for il in block:
                lookup["LowLevelIL"][il.address].append(il)

        for block in mlil:
            for mil in block:
                lookup["MediumLevelIL"][mil.address].append(mil)

    if show_ssa:
        for block in llil.ssa_form:
            for il in block:
                lookup["LowLevelILSSA"][il.address].append(il)

        for block in mlil.ssa_form:
            for mil in block:
                lookup["MediumLevelILSSA"][mil.address].append(mil)

    if show_mapped:
        mmlil = llil.mapped_medium_level_il
        for block in mmlil:
            for mil in block:
                lookup["MappedMediumLevelIL"][mil.address].append(mil)

        if show_ssa:
            for block in mmlil.ssa_form:
                for mil in block:
                    lookup["MappedMediumLevelILSSA"][mil.address].append(mil)

    for il_type in sorted(lookup):
        ils = lookup[il_type][addr]
        for il in sorted(ils):
            graph_il(g, head, il_type, il)


def graph_bnil(bv, addr):
    blocks = bv.get_basic_blocks_at(addr)  # type: List[BasicBlock]
    function = blocks[0].function  # type: Function
    g = binaryninja.FlowGraph()

    (tokens,) = [
        tokens for tokens, insn_addr in function.instructions if insn_addr == addr
    ]

    head = binaryninja.FlowGraphNode(g)
    head.lines = [tokens]
    g.append(head)

    graph_ils(bv, g, head, function, addr)

    g.show("Instruction Graph ({:#x})".format(addr))


PluginCommand.register_for_address(
    "BNIL Instruction Graph", "View BNIL Instruction Information", graph_bnil
)
