# bnil-graph
A BinaryNinja plugin to graph a BNIL instruction tree and meta-program python instruction matchers.

## Installation

1. Clone the repository to your prefered location: `$ git clone https://github.com/withzombies/bnil-graph.git`
1. Change to the Binary Ninja plugins directory: `$ cd ~/Library/Application\ Support/Binary\ Ninja/plugins`
1. Create a symlink to the folder: `$ ln -s ~/git/bnil-graph .`
1. Restart Binary Ninja

## Usage

To use bnil-graph, right click on an instruction and select "BNIL Instruction Graph". This graphs the BNIL instructions assocaited with that address and displays them as an HTML form.

Binary Ninja adds operand accessors dynamically, due to this the convenient accesors do not show up in `dir()` calls or in the api documentation. bnil-graph shows the structure of the IL instruction including its nice accessor names (such as `insn.src` for the source register or memory)

![Menu Example](https://raw.githubusercontent.com/withzombies/bnil-graph/master/images/menu.png)

Example graph:

![Example Graph](https://raw.githubusercontent.com/withzombies/bnil-graph/master/images/graph.png)

### Matchers

In addition to the graph plugin, bnil-graph also will generate a matcher function that will match the selected instructions exactly. This feature will allow new plugin developers to quickly match instructions. The intended use is to find an instruction similar to the one you want to match, generate a matcher function, then modify the generated function to better support your needs.

An example would be trying to find all MediumLevelILSSA MLIL\_CALL\_SSA instructions that take 3 parameters. I generated a matcher against an unrelated function with 0 parameters:

```python
def match_MediumLevelILSSA_140001194_0(insn):
    # mem#1 = 0x14000d49c() @ mem#0
    if insn.operation != MediumLevelILOperation.MLIL_CALL_SSA:
        return False

    # invalid
    if insn.output.operation != MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA:
        return False

    if insn.output.dest_memory != 0x1:
        return False

    if len(insn.output.dest) != 0:
        return False

    # 0x14000d49c
    if insn.dest.operation != MediumLevelILOperation.MLIL_CONST_PTR:
        return False

    if insn.dest.constant != 0x14000d49c:
        return False

    if len(insn.params) != 0:
        return False

    if insn.src_memory != 0x0:
        return False

    return True
```

We can modify this to remove some specific constraints:

```python
def match_MediumLevelILSSA_140001194_0(insn):
    # mem#1 = 0x14000d49c() @ mem#0
    if insn.operation != MediumLevelILOperation.MLIL_CALL_SSA:
        return False

    # invalid
    if insn.output.operation != MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA:
        return False

    # 0x14000d49c
    if insn.dest.operation != MediumLevelILOperation.MLIL_CONST_PTR:
        return False

    if len(insn.params) != 0:
        return False

    return True
```

We removed the call destination and the memory versioning constraints. Next, update the params check to check for 3 parameters:

```python
def match_3_param_MLIL_CALL_SSA(insn):
    if insn.operation != MediumLevelILOperation.MLIL_CALL_SSA:
        return False

    if insn.output.operation != MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA:
        return False

    if insn.dest.operation != MediumLevelILOperation.MLIL_CONST_PTR:
        return False

    if len(insn.params) != 3:
        return False

    return True
```

Now, we have a matcher which will identify MLIL\_CALL\_SSA instructions with 3 parameters! Now iterate over MLIL SSA instructions and call the matcher and we're done:

```python
if __name__ == '__main__':
    bv = binaryninja.BinaryViewType.get_view_of_file(sys.argv[1])
    bv.update_analysis_and_wait()

    for func in bv.functions:
        mlil = func.medium_level_il

        for block in mlil.ssa_form:
            for insn in block:
                if match_3_param_MLIL_CALL_SSA(insn):
                    print "Match: {}".format(insn)
```

Example matcher:

![Example Matcher](https://raw.githubusercontent.com/withzombies/bnil-graph/master/images/matcher.png)


## License

This project copyright Ryan Stortz (@withzombies) and is available under the Apache 2.0 LICENSE.
