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

Settings().register_group("bnil-graph", "BNIL Graph")
Settings().register_setting("bnil-graph.showCommon", """
    {
        "title" : "Show Common ILs",
        "type" : "boolean",
        "default" : true,
        "description" : "Show common forms (non-SSA, non-mapped) in the output."
    }
    """)

Settings().register_setting("bnil-graph.showMapped", """
    {
        "title" : "Include MMLIL",
        "type" : "boolean",
        "default" : false,
        "description" : "Show the MappedMediumLevelIL form in the output."
    }
    """)

Settings().register_setting("bnil-graph.showSSA", """
    {
        "title" : "Include SSA",
        "type" : "boolean",
        "default" : true,
        "description" : "Include SSA forms in the output."
    }
    """)

# Support python 3 and python 2
if sys.version_info > (3,):
    long = int

def show_graph_report(bv, g, name):

    # 1.3.2086-dev
    major, minor, patch = binaryninja.core_version().split('.')
    major = int(major)
    minor = int(minor)
    patch = int(patch.split('-')[0])

    if major == 1 and minor <= 3 and patch < 2086:
        g.show(name)
        return

    bv.show_graph_report(name, g)


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

    if isinstance(il, (MediumLevelILInstruction, LowLevelILInstruction)):

        tokens.append(
            InstructionTextToken(
                InstructionTextTokenType.InstructionToken, il.operation.name
            )
        )

        ops = enumerate(il.operands)
        for i, o in ops:
            edge_label, ty = il.ILOperations[il.operation][i]

            if ty == 'reg_stack_ssa_dest_and_src' or ty == 'var_ssa_dest_and_src':
                # handle the ssa_dest_and_src operand types
                next_label = 'next' if edge_label == 'prev' else 'dest'
                graph_il_insn(g, record, o, next_label)
                i, o2 = next(ops)
                graph_il_insn(g, record, o2, edge_label)
            else:
                # handle everything else
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
        elif isinstance(il, lowlevelil.SSARegister):
            tokens.append(
                InstructionTextToken(InstructionTextTokenType.TextToken, "<SSARegister>")
            )

            graph_il_insn(g, record, il.reg, "reg")
            graph_il_insn(g, record, il.version, "version")
        elif isinstance(il, mediumlevelil.SSAVariable):
            tokens.append(
                InstructionTextToken(InstructionTextTokenType.TextToken, "<SSAVariable>")
            )

            graph_il_insn(g, record, il.var, "var")
            graph_il_insn(g, record, il.version, "version")
        elif isinstance(il, function.Variable):
            tokens.append(
                InstructionTextToken(InstructionTextTokenType.TextToken, "<Variable>")
            )

            graph_il_insn(g, record, il.name, "name")
            graph_il_insn(g, record, il.type, "type")
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
    lookup = collect_ils(bv, func)

    for il_type in sorted(lookup):
        ils = lookup[il_type][addr]
        for il in sorted(ils):
            graph_il(g, head, il_type, il)


def collect_ils(bv, func):
    lookup = defaultdict(lambda: defaultdict(list))

    llil = func.low_level_il
    mlil = func.medium_level_il
    show_common = Settings().get_bool("bnil-graph.showCommon")
    show_mapped = Settings().get_bool("bnil-graph.showMapped")
    show_ssa = Settings().get_bool("bnil-graph.showSSA")

    if show_common:
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

    return lookup


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

    show_graph_report(bv, g, "Instruction Graph ({:#x})".format(addr))


def match_condition(name, o):
    match = []

    if isinstance(o, (LowLevelILInstruction, MediumLevelILInstruction)):
        if isinstance(o, LowLevelILInstruction):
            operation_class = "LowLevelILOperation"
        elif isinstance(o, MediumLevelILInstruction):
            operation_class = "MediumLevelILOperation"

        match += ["# {}".format(str(o))]
        match += [
            "if {}.operation != {}.{}:".format(name, operation_class, o.operation.name)
        ]
        match += ["    return False\n"]

        ops = enumerate(o.operands)
        for i, oo in ops:
            oo_name, ty = o.ILOperations[o.operation][i]
            if ty == 'reg_stack_ssa_dest_and_src' or ty == 'var_ssa_dest_and_src':
                next_name = 'next' if oo_name == 'prev' else 'dest'
                full_name = "{}.{}".format(name, next_name)
                cond = match_condition(full_name, oo)
                match += cond

                i, oo = next(ops)
                full_name = "{}.{}".format(name, oo_name)
                cond = match_condition(full_name, oo)
                match += cond
            else:
                full_name = "{}.{}".format(name, oo_name)
                cond = match_condition(full_name, oo)
                match += cond


    elif isinstance(o, list):
        match += ["if len({}) != {}:".format(name, len(o))]
        match += ["    return False\n"]

        # match the sub conditions too
        for i, sub_insn in enumerate(o):
            full_name = "{}[{}]".format(name, i)
            cond = match_condition(full_name, sub_insn)
            match += cond

    elif isinstance(o, (int, long)):
        match += ["if {} != {:#x}:".format(name, o)]
        match += ["    return False\n"]
    elif isinstance(o, ILRegister):
        match += ["if {}.name != '{}':".format(name, o.name)]
        match += ["    return False\n"]

    elif isinstance(o, SSARegister):
        match += ["if {}.reg.name != '{}':".format(name, o.reg.name)]
        match += ["    return False\n"]

        match += ["if {}.version != {}:".format(name, o.version)]
        match += ["    return False\n"]

    elif isinstance(o, SSAVariable):
        match += ["if {}.var.name != '{}':".format(name, o.var.name)]
        match += ["    return False\n"]

        match += ["if {}.version != {}:".format(name, o.version)]
        match += ["    return False\n"]


    else:
        match += ["if {} != {}:".format(name, o)]
        match += ["    return False\n"]

    return match


def match_bnil(bv, addr):
    blocks = bv.get_basic_blocks_at(addr)  # type: List[BasicBlock]
    function = blocks[0].function  # type: Function

    lookup = collect_ils(bv, function)

    report = ""

    for ty in lookup.keys():
        llil_insns = lookup[ty][addr]
        for idx, insn in enumerate(sorted(llil_insns)):
            f = "def match_{}_{:x}_{}(insn):\n".format(ty, addr, idx)
            cond = match_condition("insn", insn)
            f += "\n".join(["    " + x for x in cond])

            f += "\n    return True\n"

            report += f + "\n\n"

    show_plain_text_report("BNIL Matcher", report)


PluginCommand.register_for_address(
    "BNIL Instruction Graph", "View BNIL Instruction Information", graph_bnil
)

PluginCommand.register_for_address(
    "BNIL Python Match Generator",
    "Generate a python function to match the selection instructions",
    match_bnil,
)
