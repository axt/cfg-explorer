import angr
import os
import logging

l = logging.getLogger('axt.cfgexplorer')


def cfg_explore(binary,starts=[],port=5050,pie=False,lanuch=False,output=''):
    main_opts = {}
    if pie:
        main_opts['custom_base_addr'] = 0x0
    proj = angr.Project(binary,auto_load_libs=False,main_opts=main_opts)
    addrs = [proj.entry]
    pass

def create_cfg(proj,starts=[],pie=False):

