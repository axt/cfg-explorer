# cfg-explorer

CFG explorer is a simple utility which can be used to explore control flow graphs of binary programs.

It uses [angr](https://github.com/angr/angr) binary analysis framework, for CFG recovery, and renders the CFG to SVGs, with the help of [bingraphvis](http://github.com/axt/bingraphvis/). 

The generated SVGs can be navigated by clicking on the _function_ or the _callsite_ nodes.

## Note

This project is in its very early stage!

## Usage
```
$ python -m cfgexplorer /your/binary -l
```
The command above will build the CFG, spawn a webserver and open it in your browser (see `-h` for the options).

## Limitations
* works on Linux only
* at the moment, the result is simply an SVG file, i plan to add a small frontend around it

## Screenshots

### Function graph mode (`/function/0x123456`)
![fgraph][fgraph]

### CFG mode (`/cfg/0x123456`)

![cfg][cfg]


[fgraph]: http://i.imgur.com/9c1Ah9y.png
[cfg]: http://i.imgur.com/UrFroxt.png

