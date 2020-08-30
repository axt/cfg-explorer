# ---
# jupyter:
#   jupytext:
#     formats: ipynb,py:light
#     text_representation:
#       extension: .py
#       format_name: light
#       format_version: '1.5'
#       jupytext_version: 1.5.1
#   kernelspec:
#     display_name: Python 3
#     language: python
#     name: python3
# ---

# # Demo for functional usage of CFG-explorer
#
# Now, `cfg-explorer` can not only be used as a command line tool. We can also call it within a Python program.
#
# ## Download Spec CPU Benchmark 2006
#
# Save the suite outside our current repository:
#
# ```
# $ cd ..
# $ git clone https://github.com/Multi2Sim/m2s-bench-spec2006
# ```
#
# Every `.i386` file is a binary file for testing.
#
# ## Import Libraries
#
# If you have not installed `cfg_exploerer` module, you can install it with
#
# ```
# $ pip install cfg_explorer
# ```
#
# Of course, If you just want to try it without installation, it's Okay:
#
# First, to import `cfg_explore` in this subdirectory, you should include your `cfg-explorer` path into your `PATH` environment variable. You can do this by (suppose the whole `cfg-explorer` directory is located in `$HOME/cfg-explorer`):
#
# ```
# $ export PATH=$HOME/cfg-explorer:$PATH
# ```
#
# Or import it in this notebook by such an approach for that the target folder is actually the parent folder of this file:

# +
import os
import sys
from pathlib import Path

sys.path.insert(0,str(Path().resolve().parent))
# -

# ##  Usages of `cfg_explore` Function

from cfgexplorer import cfg_explore

# ### Lanuch an interactive web app
#
# Now, call `cfg_explore` with the only argument `binary`, which is the path of the bianry file we prepare to analysis. After running, it will host a website on http://127.0.0.1:5050/ to show the *control flow graph* of the file. You can specify the port by `port` parameter.

cfg_explore(binary='../../m2s-bench-spec2006/999.specrand/specrand_base.i386')

# Whenever you want to shut down the app, just interrupt the function. For example, in this notebook, click on <kbd>interrupt the kernel</kbd>buttom on the toolbar.

# ### Generate multiple formats of outputs
#
# Instead of launching a web app, you can also let `cfg_explore` generate output files by specifying `output` argument.
#
# For instance, we can get the `svg` format CFG of `specrand_base.i386'` using:

cfg_explore(binary='../../m2s-bench-spec2006/999.specrand/specrand_base.i386',output='./test.svg')

# `.svg` files can be opened by web-browser directly, it can also be displayed in this notebook:

from IPython.core.display import SVG
display(SVG('test.svg'))

# There are also a bunch of formats that `cfg_explore` can handle. The only thing you need to do is to specify proper suffix (i.e. extension name) in path which is passed as`output` argument.
#
# Current supported formats are listed as below:

formats = [
    'canon', 'cmap', 'cmapx', 'cmapx_np', 'dot', 'fig', 'gd', 'gd2', 'gif',
    'imap', 'imap_np', 'ismap', 'jpe', 'jpeg', 'jpg', 'mp', 'pdf', 'plain',
    'plain-ext', 'png', 'ps', 'ps2', 'svg', 'svgz', 'vml', 'vmlz', 'vrml',
    'wbmp', 'xdot', 'raw'
]

# Try all formats by:

for format in formats:
    cfg_explore(binary='../../m2s-bench-spec2006/999.specrand/specrand_base.i386',output='./test.'+format)

# View the output `png`:
#
# ![](test.png)

# + [markdown] pycharm={"name": "#%% md\n"}
# ### Traversal a large folder to generate all CFGs
#
# We still use `m2s-bench-spec2006` as an example.
#
# Assume that we need to analyze all binary files in this folder. Wrapping `cfg-explorer` as a function makes the task more flexible inside a Python script.
#
# First, get all potential binary files for analysis:
# -

from glob import glob
progs = sorted(glob('../../m2s-bench-spec2006/*/*.i386'))
progs

# create a directory to store the outputs
out_dir = './output'
if not os.path.exists(out_dir):
    os.mkdir(out_dir)

# + [markdown] pycharm={"name": "#%% md\n"}
# Then, we can simply call `cfg_explore` function inside loops. Keep it alone, we just need to wait for generating all '.svg' files.
#
# **Note**: it might take a extremely long time. Be patient.
# -

for p in progs:
    name = p.split('/')[3]
    print('start analysis of:',name)
    output_file = os.path.join(out_dir, name + '.svg')
    if not os.path.exists(output_file):
        cfg_explore(binary=p,output=output_file)

# + [markdown] pycharm={"name": "#%% md\n"}
# Now, you can view all outputs in `out_dir`.
#
#
