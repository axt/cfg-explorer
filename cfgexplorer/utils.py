import angr
import os
import logging

l = logging.getLogger('axt.cfgexplorer')

from .explorer import CFGExplorer
from .endpoint import CFGVisEndpoint, FGraphVisEndpoint

support_type = [
    'canon', 'cmap', 'cmapx', 'cmapx_np', 'dot', 'fig', 'gd', 'gd2', 'gif',
    'imap', 'imap_np', 'ismap', 'jpe', 'jpeg', 'jpg', 'mp', 'pdf', 'plain',
    'plain-ext', 'png', 'ps', 'ps2', 'svg', 'svgz', 'vml', 'vmlz', 'vrml',
    'wbmp', 'xdot', 'raw'
]


def cfg_explore(binary, starts=[], port=5000, pie=False, launch=False, output=''):
    """
    :param binary: the path of binary file for analysis
    :type binary: str
    :param starts: the start points (address) in CFGs, if none, the CFG will start with main func entry address
    :type starts: list
    :param port: server port to host the web app. make sure the port is idle now.
    :type port: int
    :param pie: whether the analysis position independent
    :type pie: bool
    :param launch: Launch a browser to view CFG immediately
    :type launch: bool
    :param output: the output file path. only support certain formats. If leave it an empty string, no output will be generated and the interactive web app will start. Otherwise, no app will be launched and the CFGs will be exported to specified files.
    :type output: str
    :return: None
    :rtype: None
    """
    main_opts = {}
    if pie:
        main_opts['custom_base_addr'] = 0x0
    proj = angr.Project(binary, auto_load_libs=False, main_opts=main_opts)

    # create CFG
    if starts:
        addrs = get_addrs(proj, starts)
        cfg = proj.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True, symbols=False,
                                    function_prologues=False, force_complete_scan=False, collect_data_references=False,
                                    start_at_entry=False, function_starts=addrs, resolve_indirect_jumps=True)
    else:
        cfg = proj.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True, symbols=True,
                                    function_prologues=True, force_complete_scan=True, collect_data_references=False,
                                    resolve_indirect_jumps=True)
        addrs = get_addrs(proj, starts)

    # lanuch a flask app
    if not output:
        lanuch_app(launch, port)
        app = CFGExplorer(start_url='/api/cfg/%#08x' % addrs[0], port=port)
        app.add_vis_endpoint(CFGVisEndpoint('cfg', cfg))
        app.add_vis_endpoint(FGraphVisEndpoint('function', proj, cfg))
        try:
            app.run()
        except:
            pass
    else:
        fname, ext = os.path.splitext(output)
        ext = ext[1:]
        if ext in support_type:
            endpoint = CFGVisEndpoint('cfg', cfg)
            for addr in addrs:
                endpoint.serve(addr, fname, ext)
        else:
            l.error('Wrong output file format! Only support for the following formats: ' + str(support_type))
            raise Exception('Invalid Input')


def get_addrs(proj, starts=[]):
    """
    Get all start addresses in the project for analysis
    :param proj: the project to analyze
    :type proj: angr.Project
    :param starts: start address list
    :type starts: list
    :return: all possible start addresses
    :rtype: list
    """
    if starts:
        addrs = []
        for s in starts:
            try:
                addr = int(s, 16)
                addrs.append(addr)
            except:
                sym = proj.loader.main_bin.get_symbol(s)
                if sym:
                    addr = sym.addr
                    if addr:
                        addrs.append(addr)
                else:
                    l.warning("Starting address unrecognized %s", s)
    else:
        if 'main' in proj.kb.functions:
            addrs = [proj.kb.functions['main'].addr]
        else:
            addrs = [proj.entry]
    return addrs


def lanuch_app(prompt=False, port=5000):
    """
    :param prompt: whether lannuch a browser immediately
    :type prompt: true
    :param port: port to host the flask app
    :type port: int
    :return: None
    :rtype: None
    """
    if prompt:
        try:
            os.system('xdg-open http://localhost:%d/' % port)
        except Exception as e:
            l.error(e)
    else:
        l.info('http://localhost:%d/' % port)
