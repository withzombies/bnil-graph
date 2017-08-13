# bnil-graph
A BinaryNinja plugin to graph a BNIL instruction tree

## Dependencies

This plugin requires [graphviz](http://www.graphviz.org/).

You can install it on macOS via brew:
```bash
$ brew install graphviz
```

Or on Ubuntu via apt:
```bash
$ sudo apt install graphviz
```

## Installation

1. Clone the repository to your prefered location: `$ git clone https://github.com/withzombies/bnil-graph.git`
1. Change to the Binary Ninja plugins directory: `$ cd ~/Library/Application\ Support/Binary\ Ninja/plugins`
1. Create a symlink to the folder: `$ ln -s ~/git/bnil-graph .`
1. Restart Binary Ninja

## Usage

To use bnil-graph, right click on an instruction and select "BNIL Instruction Graph". This graphs the BNIL instructions assocaited with that address and displays them as an HTML form.

![Menu Example](https://raw.githubusercontent.com/withzombies/bnil-graph/master/images/menu.png)

Example graph:

![Example Graph](https://raw.githubusercontent.com/withzombies/bnil-graph/master/images/graph.png)


## License

This project copyright Ryan Stortz (@withzombies) and is available under the Apache 2.0 LICENSE.
