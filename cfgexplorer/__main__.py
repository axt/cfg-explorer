import logging
l = logging.getLogger('cfgexplorer')
l.setLevel(logging.INFO)

import os
import argparse
import angr
import tempfile
import traceback

from bingraphvis import *
from bingraphvis.angr import *


from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer


from bingraphvis.base import NodeAnnotator

class XRefFunctions(NodeAnnotator):
    def __init__(self):
        super(XRefFunctions, self).__init__()

    def annotate_node(self, node):
        if type(node.obj).__name__ == 'Function':
            node.url = '/function/%#x' % node.obj.addr
            node.tooltip = 'Click to navigate to function %#x' % node.obj.addr

class XRefCFGCallsites(NodeAnnotator):
    def __init__(self, project):
        super(XRefCFGCallsites, self).__init__()
        self.project = project

    def annotate_node(self, node):
        func = self.project.kb.functions[node.obj.function_address]
        if node.obj.addr in func.get_call_sites():
            target = func.get_call_target(node.obj.addr)
            node.url = '/cfg/%#x' % target
            node.tooltip = 'Click to navigate to function %#x' % target

class R(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path.startswith('/function/'):
                addr_str = self.path.split("/")[2]
                addr = int(addr_str,16)

                func = self.server.project.kb.functions[addr]
                l.info("Found function %x %s", func.addr, func.name)

                outfile = None
                try:
                    outfile = tempfile.mktemp(dir="/dev/shm/", prefix="cfg-explorer-")

                    vis = AngrVisFactory().default_func_graph_pipeline(self.server.project)
                    vis.add_node_annotator(XRefFunctions())
                    vis.set_output(DotOutput(outfile, format="svg"))
                    vis.process(func.transition_graph)

                    self.send_response(200)
                    self.send_header('Content-type', 'image/svg+xml')
                    self.end_headers()
                    with open(outfile + '.svg') as f:
                        self.wfile.write(f.read())

                finally:
                    if outfile and os.path.exists(outfile + '.svg'):
                        os.remove(outfile + '.svg')

            if self.path.startswith('/cfg/'):
                addr_str = self.path.split("/")[2]
                addr = int(addr_str,16)

                outfile = None
                try:
                    outfile = tempfile.mktemp(dir="/dev/shm/", prefix="cfg-explorer-")

                    vis = AngrVisFactory().default_cfg_pipeline(self.server.cfg, asminst=True)
                    vis.add_node_annotator(XRefCFGCallsites(self.server.project))
                    vis.set_output(DotOutput(outfile, format="svg"))
                    vis.process(self.server.cfg.graph, filter=lambda node:node.obj.function_address == addr)

                    self.send_response(200)
                    self.send_header('Content-type', 'image/svg+xml')
                    self.end_headers()
                    with open(outfile + '.svg') as f:
                        self.wfile.write(f.read())

                finally:
                    if outfile and os.path.exists(outfile + '.svg'):
                        os.remove(outfile + '.svg')

        except Exception, e:
            traceback.print_exc()
            l.error("Exception %s", e)
            self.send_response(400)

class S(HTTPServer):
    def __init__(self, args, project, cfg):
        self.args = args
        self.project = project
        self.cfg = cfg
        HTTPServer.__init__(self, ('127.0.0.1', self.args.port), R)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="count", help="increase output verbosity")
    parser.add_argument('binary', metavar='binary', type=str, help='the binary to explore')
    parser.add_argument('-s', '--start', nargs="*", dest='starts', help='start addresses')
    parser.add_argument('-p', '--port', dest='port', help='server port', type=int, default=8000)
    parser.add_argument('-l', '--launch',  dest='launch', action="store_true", help='launch browser')

    args = parser.parse_args()

    project = angr.Project(args.binary, load_options={'auto_load_libs': False})

    addrs = [project.entry]

    if not args.starts:
        cfg = project.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True, symbols=True, function_prologues=True, force_complete_scan=True, collect_data_references=False, resolve_indirect_jumps=True)
        if 'main' in project.kb.functions:
            addrs = [ project.kb.functions['main'].addr ]
    else:
        addrs = map(lambda s:int(s,16), args.starts)
        cfg = project.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True, symbols=False, function_prologues=False, force_complete_scan=False, collect_data_references=False, start_at_entry=False, function_starts = addrs, resolve_indirect_jumps=True)

    httpd = S(args, project, cfg)

    if args.launch:
        try:
            for addr in addrs:
                os.system('xdg-open http://localhost:%d/function/%#x' % (args.port, addr))
        except:
            pass
    else:
        for addr in addrs:
            l.info('http://localhost:%d/function/%#x' % (args.port, addr))

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()

if __name__ == '__main__':
    main()
