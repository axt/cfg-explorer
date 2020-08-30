import logging

l = logging.getLogger('axt.cfgexplorer')

import argparse
import angr
import os

from .explorer import CFGExplorer
from .endpoint import CFGVisEndpoint, FGraphVisEndpoint

support_type = [
    'canon', 'cmap', 'cmapx', 'cmapx_np', 'dot', 'fig', 'gd', 'gd2', 'gif',
    'imap', 'imap_np', 'ismap', 'jpe', 'jpeg', 'jpg', 'mp', 'pdf', 'plain',
    'plain-ext', 'png', 'ps', 'ps2', 'svg', 'svgz', 'vml', 'vmlz', 'vrml',
    'wbmp', 'xdot', 'raw'
]


class CFGExplorerCLI(object):
    """
    By default, -l and -p will be invalid if you specify the -o argument, it will also give an output instead of launching a web app.
    """
    def __init__(self):
        self.parser = None
        self.args = None
        self.project = None
        self.cfg = None

        self._create_parser()
        self.args = self.parser.parse_args()

        self.ext = 'svg'
        self.fname = ''
        if self.args.outfile:
            self.fname, self.ext = os.path.splitext(self.args.outfile)
            if self.ext:
                self.ext = self.ext[1:]
            if self.ext not in support_type:
                l.error('Wrong output file format! Only support for the following formats:' + str(support_type))
                raise Exception('Invalid Input')

        self._create_cfg()

        self._postprocess_cfg()
        if self.fname:
            endpoint = CFGVisEndpoint('cfg', self.cfg)
            for addr in self.addrs:
                endpoint.serve(addr, fname=self.fname, format=self.ext)
        else:
            self._launch()
            self.app = CFGExplorer(start_url='/api/cfg/%#08x' % self.addrs[0], port=self.args.port)
            self.add_endpoints()

    def run(self):
        """
        Build the app. If you specify the output file, the func will not be called
        :return: None
        :rtype: None
        """
        try:
            if not self.fname:
                self.app.run()
        except KeyboardInterrupt:
            pass

    def _create_parser(self):
        """
        Create a parser to take arguments
        :return:None
        :rtype: None
        """
        self._create_default_parser()
        self._extend_parser()

    def _create_default_parser(self):
        """
        Get all arguments in command lines
        :return: None
        :rtype: None
        """
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-v", "--verbose", action="count", help="increase output verbosity")
        self.parser.add_argument('binary', metavar='binary', type=str, help='the binary to explore')
        self.parser.add_argument('-s', '--start', nargs="*", dest='starts', help='start addresses')
        self.parser.add_argument('-P', '--port', dest='port', help='server port', type=int, default=5000)
        self.parser.add_argument('-p', '--pie', dest='pie', action='store_true', help='is position independent')
        self.parser.add_argument('-l', '--launch', dest='launch', action='store_true', help='launch browser')
        self.parser.add_argument('-o', '--output', default='', dest='outfile', help="output file path, only support for "+ str(support_type))

    def _extend_parser(self):
        pass

    def _create_cfg(self):
        """
        Analyze the binary file and get
        1. Get proper start addresses
        2. Generate CFG by simple static analysis
        3. Store the result in class
        :return: None
        :rtype: None
        """
        main_opts = {}
        if self.args.pie:
            main_opts['custom_base_addr'] = 0x0

        self.project = angr.Project(self.args.binary, load_options={'auto_load_libs': False, 'main_opts': main_opts})

        if not self.args.starts:
            self.cfg = self.project.analyses.CFGFast(fail_fast=False, normalize=True, show_progressbar=True,
                                                     symbols=True, function_prologues=True, force_complete_scan=True,
                                                     collect_data_references=False, resolve_indirect_jumps=True)
            if 'main' in self.project.kb.functions:
                self.addrs = [self.project.kb.functions['main'].addr]
            else:
                self.addrs = [self.project.entry]
        else:
            self.addrs = []

            for s in self.args.starts:
                addr = None

                try:
                    addr = int(s, 16)
                except:
                    pass

                if not addr:
                    sym = self.project.loader.main_object.get_symbol(s)
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
        """
        Give a log info to reminder the app link. If you set --lanuch as True (using -l), it will automatically open the browser and jump to the link.
        :return: None
        :rtype: None
        """
        if self.args.launch:
            try:
                for addr in self.addrs:
                    os.system('xdg-open http://localhost:%d/' % (self.args.port))
            except Exception as e:
                print(e)
                pass
        else:
            for addr in self.addrs:
                l.info('http://localhost:%d/' % (self.args.port))

    def add_endpoints(self):
        """
        Create VisEndpoints for CFG and add it to CFGExplorer
        :return: None
        :rtype: None
        """
        self.app.add_vis_endpoint(CFGVisEndpoint('cfg', self.cfg))
        self.app.add_vis_endpoint(FGraphVisEndpoint('function', self.project, self.cfg))
