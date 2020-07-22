import logging

l = logging.getLogger('axt.cfgexplorer')

import argparse
import angr
import os

from .explorer import CFGExplorer
from .endpoint import CFGVisEndpoint, FGraphVisEndpoint
from networkx.drawing.nx_agraph import write_dot


class CFGExplorerCLI(object):

    def __init__(self):
        self.parser = None
        self.args = None
        self.project = None
        self.cfg = None

        self._create_parser()
        self.args = self.parser.parse_args()

        self.ext = 'svg'
        self.fname = ''
        if not self.args.outfile:
            self.fname, self.ext = os.path.splitext(self.args.outfile)
            if self.ext != '.svg' and self.ext != '.dot':
                l.error('Wrong output file foramt! Only support for .svg and .dot')
                raise Exception('Invalid Input')

        self._create_cfg()
        if self.ext == '.dot':
            write_dot(self.cfg.graph, self.args.outfile)
            l.info("CFG is exported to " + self.args.outfile)
        else:
            self._postprocess_cfg()
            if self.fname:
                endpoint = CFGVisEndpoint('cfg', self.cfg)
                for addr in self.addrs:
                    endpoint.serve(addr, fname=self.args.outfile)
            else:
                self._launch()
                self.app = CFGExplorer(start_url='/api/cfg/%#08x' % self.addrs[0], port=self.args.port)
                self.add_endpoints()

    def run(self):
        try:
            self.app.run()
        except KeyboardInterrupt:
            pass

    def _create_parser(self):
        self._create_default_parser()
        self._extend_parser()

    def _create_default_parser(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-v", "--verbose", action="count", help="increase output verbosity")
        self.parser.add_argument('binary', metavar='binary', type=str, help='the binary to explore')
        self.parser.add_argument('-s', '--start', nargs="*", dest='starts', help='start addresses')
        self.parser.add_argument('-P', '--port', dest='port', help='server port', type=int, default=5000)
        self.parser.add_argument('-p', '--pie', dest='pie', action='store_true', help='is position independent')
        self.parser.add_argument('-l', '--launch', dest='launch', action='store_true', help='launch browser')
        self.parser.add_argument('-o', '--output', default='', dest='outfile', help="output file path")

    def _extend_parser(self):
        pass

    def _create_cfg(self):
        main_opts = {}
        if self.args.pie:
            main_opts['custom_base_addr'] = 0x0

        self.project = angr.Project(self.args.binary, load_options={'auto_load_libs': False, 'main_opts': main_opts})

        self.addrs = [self.project.entry]

        if not self.args.starts:
            self.cfg = self.project.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True,
                                                     symbols=True, function_prologues=True, force_complete_scan=True,
                                                     collect_data_references=False, resolve_indirect_jumps=True)
            if 'main' in self.project.kb.functions:
                self.addrs = [self.project.kb.functions['main'].addr]
        else:
            self.addrs = []

            for s in self.args.starts:
                addr = None

                try:
                    addr = int(s, 16)
                except:
                    pass

                if not addr:
                    sym = self.project.loader.main_bin.get_symbol(s)
                    if sym:
                        addr = sym.addr

                if addr:
                    self.addrs.append(addr)
                else:
                    l.warning("Starting address unrecognized %s", s)

            self.cfg = self.project.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True,
                                                     symbols=False, function_prologues=False, force_complete_scan=False,
                                                     collect_data_references=False, start_at_entry=False,
                                                     function_starts=self.addrs, resolve_indirect_jumps=True)

    def _postprocess_cfg(self):
        pass

    def _launch(self):
        if self.args.launch:
            try:
                for addr in self.addrs:
                    os.system('xdg-open http://localhost:%d/' % (self.args.port))
            except Exception as e:
                print(e)
                pass
        else:
            if not self.args.outfile:
                for addr in self.addrs:
                    l.info('http://localhost:%d/' % (self.args.port))

    def add_endpoints(self):
        self.app.add_vis_endpoint(CFGVisEndpoint('cfg', self.cfg))
        self.app.add_vis_endpoint(FGraphVisEndpoint('function', self.project, self.cfg))
