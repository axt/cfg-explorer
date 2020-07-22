import logging

l = logging.getLogger('axt.cfgexplorer')

import os
import tempfile
from bingraphvis import *
from bingraphvis.angr import *
from flask import Response
from .annotator import *


class VisEndpoint(object):
    def __init__(self, name):
        self.name = name

    def create_vis(self, addr):
        raise NotImplementedError()

    def xref_vis(self, vis, addr):
        raise NotImplementedError()

    def annotate_vis(self, vis, addr):
        pass

    def process_vis(self, vis, addr):
        raise NotImplementedError()

    def serve(self, addr_str, fname=''):
        addr = int(addr_str, 16)

        outfile = fname if fname else os.path.join(tempfile.mktemp(dir="/dev/shm/", prefix="cfg-explorer-"), '.svg')

        try:
            vis = self.create_vis(addr)
            self.annotate_vis(vis, addr)
            self.xref_vis(vis, addr)

            vis.set_output(DotOutput(outfile, format="svg"))
            self.process_vis(vis, addr)

            if not fname:
                with open(outfile) as f:
                    return Response(f.read(), mimetype='image/svg+xml')
            else:
                l.info("CFG is exported to" + outfile)
        finally:
            if outfile and not fname and os.path.exists(outfile + '.svg'):
                os.remove(outfile + '.svg')


class CFGVisEndpoint(VisEndpoint):
    def __init__(self, name, cfg):
        super(CFGVisEndpoint, self).__init__(name)
        self.cfg = cfg

    def create_vis(self, addr):
        vis = AngrVisFactory().default_cfg_pipeline(self.cfg, asminst=True)
        return vis

    def xref_vis(self, vis, addr):
        vis.add_node_annotator(XRefCFGCallsites(self.cfg.project, self.name))

    def process_vis(self, vis, addr):
        vis.process(self.cfg.graph, filter=lambda node: node.obj.function_address == addr)


class FGraphVisEndpoint(VisEndpoint):
    def __init__(self, name, project, kb=None):
        super(FGraphVisEndpoint, self).__init__(name)
        self.project = project
        self.kb = kb if kb else project.kb

    def create_vis(self, addr):
        vis = AngrVisFactory().default_func_graph_pipeline(self.project)
        return vis

    def xref_vis(self, vis, addr):
        vis.add_node_annotator(XRefFunctions(self.name))

    def process_vis(self, vis, addr):
        # import IPython; IPython.embed()
        vis.process(self.kb.functions[addr].transition_graph)
