import angr
import os
import logging

l = logging.getLogger('axt.cfgexplorer')

from .explorer import CFGExplorer
from .endpoint import CFGVisEndpoint, FGraphVisEndpoint
from networkx.drawing.nx_agraph import write_dot


def cfg_explore(binary, starts=[], port=5050, pie=False, lanuch=False, output=''):
    main_opts = {}
    if pie:
        main_opts['custom_base_addr'] = 0x0
    proj = angr.Project(binary, auto_load_libs=False, main_opts=main_opts)
    addrs = get_addrs(proj, starts)

    # create CFG
    if starts:
        cfg = proj.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True, symbols=False,
                                    function_prologues=False, force_complete_scan=False, collect_data_references=False,
                                    start_at_entry=False, function_starts=addrs, resolve_indirect_jumps=True)
    else:
        cfg = proj.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True, symbols=True,
                                    function_prologues=True, force_complete_scan=True, collect_data_references=False,
                                    resolve_indirect_jumps=True)

    # lanuch a flask app
    if not output:
        lanuch_app(lanuch, port)
        app = CFGExplorer(start_url='/api/cfg/%#08x' % addrs[0], port=port)
        app.add_vis_endpoint(CFGVisEndpoint('cfg', cfg))
        app.add_vis_endpoint(FGraphVisEndpoint('function', proj, cfg))
        try:
            app.run()
        except:
            pass
    else:
        _, ext = os.path.splitext(output)
        if ext == '.dot':
            write_dot(cfg.graph, output)
        elif ext == '.svg':
            endpoint = CFGVisEndpoint('cfg', cfg)
            for addr in addrs:
                endpoint.serve(addr, output)
        else:
            l.error('Wrong output file foramt! Only support for .svg and .dot')
            raise Exception('Invalid Input')


def get_addrs(proj, starts=[]):
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
            addrs = []
    return addrs


def lanuch_app(prompt=False, port=5050):
    if prompt:
        try:
            os.system('xdg-open http://localhost:%d/' % port)
        except Exception as e:
            l.error(e)
    else:
        l.info('http://localhost:%d/' % port)
