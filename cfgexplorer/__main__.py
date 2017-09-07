import logging
l = logging.getLogger('cfgexplorer')
l.setLevel(logging.INFO)

import os
import argparse
import angr
import tempfile

from bingraphvis import *
from bingraphvis.angr import *

from bingraphvis.base import NodeAnnotator

class XRefFunctions(NodeAnnotator):
    def __init__(self):
        super(XRefFunctions, self).__init__()

    def annotate_node(self, node):
        if type(node.obj).__name__ == 'Function':
            node.url = '/api/function/%#x' % node.obj.addr
            node.tooltip = 'Click to navigate to function %#x' % node.obj.addr

class XRefCFGCallsites(NodeAnnotator):
    def __init__(self, project):
        super(XRefCFGCallsites, self).__init__()
        self.project = project

    def annotate_node(self, node):
        func = self.project.kb.functions[node.obj.function_address]
        if node.obj.addr in func.get_call_sites():
            target = func.get_call_target(node.obj.addr)
            node.url = '/api/cfg/%#x' % target
            node.tooltip = 'Click to navigate to function %#x' % target

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="count", help="increase output verbosity")
    parser.add_argument('binary', metavar='binary', type=str, help='the binary to explore')
    parser.add_argument('-s', '--start', nargs="*", dest='starts', help='start addresses')
    parser.add_argument('-P', '--port', dest='port', help='server port', type=int, default=5000)
    parser.add_argument('-p', '--pie', dest='pie', action='store_true', help='is position independent')
    parser.add_argument('-l', '--launch',  dest='launch', action='store_true', help='launch browser')

    args = parser.parse_args()


    main_opts = {}
    if args.pie:
        main_opts['custom_base_addr'] = 0x0

    project = angr.Project(args.binary, load_options={'auto_load_libs': False, 'main_opts': main_opts})

    addrs = [project.entry]

    if not args.starts:
        cfg = project.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True, symbols=True, function_prologues=True, force_complete_scan=True, collect_data_references=False, resolve_indirect_jumps=True)
        if 'main' in project.kb.functions:
            addrs = [ project.kb.functions['main'].addr ]
    else:
        addrs = []

        for s in args.starts:
            addr = None
            try:
                addr = int(s,16)
            except:
                pass
                
            if not addr:
                sym = project.loader.main_bin.get_symbol(s)
                if sym:
                    addr = sym.addr

            if addr:
                addrs.append(addr)
            else:
                l.warning("Starting address unrecognized %s", s)
                
        cfg = project.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True, symbols=False, function_prologues=False, force_complete_scan=False, collect_data_references=False, start_at_entry=False, function_starts = addrs, resolve_indirect_jumps=True)


    if args.launch:
        try:
            for addr in addrs:
                os.system('xdg-open http://localhost:%d/function/%#x' % (args.port, addr))
        except:
            pass
    else:
        for addr in addrs:
            l.info('http://localhost:%d/api/cfg/%#x' % (args.port, addr))

    try:
        app = App(args, project, cfg)
        app.run()
        pass
    except KeyboardInterrupt:
        pass




from flask import Flask, Response, send_from_directory
            
class App(object):
    def __init__(self, args, project, cfg):
        self.args = args
        self.project = project
        self.cfg = cfg
        
        self._static_files_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../static/")
        self._app = Flask('cica') #__name__
        self._app.add_url_rule('/api/cfg/<string:addr_str>', 'api_cfg', self._serve_api_cfg, methods=['GET'])
        self._app.add_url_rule('/api/fgraph/<string:addr_str>', 'api_fgraph', self._serve_api_fgraph, methods=['GET'])

        self._app.add_url_rule('/<path:file_relative_path_to_root>', 'serve_page', self._serve_page, methods=['GET'])
        self._app.add_url_rule('/', 'index', self._goto_index, methods=['GET'])
        self._cfg_addrs = set()
        
    def _goto_index(self):
        return self._serve_page("index.html")

    def _serve_page(self, file_relative_path_to_root):
        return send_from_directory(self._static_files_root, file_relative_path_to_root)

    def _serve_api_cfg(self, addr_str):
        addr = int(addr_str,16)
        
        if addr in self._cfg_addrs:
            self._cfg_addrs.remove(addr)
        else:
            self._cfg_addrs.add(addr)
        
        outfile = None
        try:
            outfile = tempfile.mktemp(dir="/dev/shm/", prefix="cfg-explorer-")

            vis = AngrVisFactory().default_cfg_pipeline(self.cfg, asminst=True)
            vis.add_node_annotator(XRefCFGCallsites(self.project))
            
            #vis.add_clusterer(AngrCallstackKeyClusterer())
            #vis.add_clusterer(ColorDepthClusterer(palette='greens'))

            vis.set_output(DotOutput(outfile, format="svg"))
            #vis.process(self.cfg.graph, filter=lambda node:node.obj.function_address == addr)
            vis.process(self.cfg.graph, filter=lambda node:node.obj.function_address in self._cfg_addrs)
            


            with open(outfile + '.svg') as f:
                return Response(f.read(), mimetype='image/svg+xml')
        finally:
            if outfile and os.path.exists(outfile + '.svg'):
                os.remove(outfile + '.svg')

    def _serve_api_fgraph(self, addr_str):
        addr = int(addr_str,16)
        func = self.project.kb.functions[addr]
        l.info("Found function %x %s", func.addr, func.name)

        outfile = None
        try:
            outfile = tempfile.mktemp(dir="/dev/shm/", prefix="cfg-explorer-")

            vis = AngrVisFactory().default_func_graph_pipeline(self.project)
            vis.add_node_annotator(XRefFunctions())
            vis.set_output(DotOutput(outfile, format="svg"))
            vis.process(func.transition_graph)

            with open(outfile + '.svg') as f:
                return Response(f.read(), mimetype='image/svg+xml')
        finally:
            if outfile and os.path.exists(outfile + '.svg'):
                os.remove(outfile + '.svg')

    def run(self):
        self._app.run(debug=True, use_reloader=False)
    
if __name__ == '__main__':
    main()
