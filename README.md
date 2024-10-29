# cfg-explorer

[![license](https://img.shields.io/github/license/axt/cfg-explorer?style=flat-square)](https://github.com/axt/cfg-explorer)
![platform](https://img.shields.io/badge/platform-Linux-yellowgreen?style=flat-square)
[![pyversion](https://img.shields.io/pypi/pyversions/cfg-explorer?style=flat-square)](https://pypi.org/project/cfg-explorer/)
[![version](https://img.shields.io/pypi/v/cfg-explorer?style=flat-square)](https://pypi.org/project/cfg-explorer/)
[![download](https://img.shields.io/pypi/dm/cfg-explorer?style=flat-square)](https://pypi.org/project/cfg-explorer/)


CFG explorer is a simple utility which can be used to explore control flow graphs of binary programs.

It uses [angr](https://github.com/angr/angr) binary analysis framework, for CFG recovery, and renders the CFG to SVGs, with the help of [bingraphvis](http://github.com/axt/bingraphvis/). 

The generated SVGs can be navigated by clicking on the _function_ or the _callsite_ nodes.

Besides, now it can also export multiple formats of static CFG files to your local machine, including:

- .canon
- .cmap
- .cmapx
- .cmapx_np
- **.dot**
- .fig
- .gd
- .gd2
- .gif
- .imap
- .imap_np
- .ismap
- .jpe
- **.jpeg**
- **.jpg**
- .mp
- **.pdf**
- .plain
- .plain-ext
- **.png**
- .ps
- .ps2
- **.svg**
- .svgz
- .vml
- .vmlz
- .vrml
- .wbmp
- .xdot
- **.raw**

CFGs starting from multiple start addresses or for multiple functions can also be automatically exported to multiple files at once with different suffixes in their filenames.

## Quick Start: Use Docker Image

1. build the docker image

```bash
docker build -t cfg-explorer .
```

2. run the docker container, mount the directory containing the binary to be analyzed to `/data` in the container


For example, use [`examples/specrand_base.i386`](./examples/specrand_base.i386) as the binary and output the CFG to `./output/cfg.pdf`:

```bash
docker run -v $(pwd)/examples/specrand_base.i386:/data/binary  \
    -v $(pwd)/output:/output cfg-explorer /data/binary -o /output/cfg.pdf
```

Or let it start a web server and open the browser to view the CFG:


```bash
docker run -p 5000:5000 -v $(pwd)/examples/specrand_base.i386:/data/binary  \
 cfg-explorer /data/binary
```

You can view the CFG in your browser by visiting `http://localhost:5000/api/cfg/0x[entry_address]` according to the output of the command.


Or you can use the quick run image (available as [yangzhou301/cfg-explorer-quickrun](https://hub.docker.com/repository/docker/yangzhou301/cfg-explorer-quickrun/general)) if you don't want to build the binary

```bash
docker build -t cfg-explorer-quickrun -f Dockerfile.quickrun .
```

Mount the directory you want to build to `app/input` and set its output as `target`. You can refer to ['examples/helloworld'](./examples/helloworld) for a simple example.

```bash
docker run -p 5000:5000 -v $(pwd)/examples/helloworld:/app/input cfg-explorer-quickrun
```


## Note

This project is in its very early stage!

## Install

```
$ pip install cfg-explorer
```

## Usage

### CLI

After installation, `cfg_explorer` can be easily called in command lines as:

```
$ cfgexplorer --help

usage: cfgexplorer [-h] [-v] [-s [STARTS [STARTS ...]]] [-P PORT] [-p] [-l]
                   [-o OUTFILE]
                   binary

positional arguments:
  binary                the binary to explore

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -s [STARTS [STARTS ...]], --start [STARTS [STARTS ...]]
                        start addresses
  -P PORT, --port PORT  server port
  -p, --pie             is position independent
  -l, --launch          launch browser
  -o OUTFILE, --output OUTFILE
                        output file path, only support for ['canon', 'cmap',
                        'cmapx', 'cmapx_np', 'dot', 'fig', 'gd', 'gd2', 'gif',
                        'imap', 'imap_np', 'ismap', 'jpe', 'jpeg', 'jpg',
                        'mp', 'pdf', 'plain', 'plain-ext', 'png', 'ps', 'ps2',
                        'svg', 'svgz', 'vml', 'vmlz', 'vrml', 'wbmp', 'xdot',
                        'raw']
```

For example:

```
$ cfgexplorer /your/binary -l
```

The command above will build the CFG, spawn a web server, and open it in your browser.

### Module

You can also utilize `cfg_explore` function in it as other common modules in Python:

```py
from cfgexplorer import cfg_explore

cfg_explore(binary=r'/your/binary', launch=True)
```

The codes will do what the `cfgexplorer` does in the previous example. If you want to shut down the app, you need to interrupt your Python interpreter as well. So the function is more often used by specifying `output` to generate output files in a Python program like:

```py
cfg_explore(binary=r'/your/binary', output='./cfg_output.svg')
```

The code above exports CFG as `svg` format to file path `./cfg_output.svg`

The function is defined as follow:

```py
cfg_explore(binary, starts=[], port=5000, pie=False, launch=False, output='')
```

- binary(*str*): the path of the binary file to analysis
- starts(*list*): the start points (address) in CFGs, if none, the CFG will start with main func entry address
- port(*int*): server port to host the web app. make sure the port is idle now.
- pie(*bool*): whether the analysis position-independent
- launch(*bool*): Whether launch a browser to view CFG immediately
- output(*str*): the output file path. only support certain formats. If you leave it an empty string, no output will be generated and the interactive web app will start. Otherwise, no app will be launched and the CFGs will be exported to specified files.

Detailed usages of this function are available in [examples/demo.ipynb](./examples/demo.ipynb).

## Annotation Style

Edges:


Edge class | Color | Style
---------|----------|---------
Conditional True | Green | 
Conditional False | Red | 
Unconditional | Blue|
Next | Blue | Dashed
Call | Black | 
Return | Gray | 
Fake Return | Gray | Dotted
Unknown | Orange | 



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

