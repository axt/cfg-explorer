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

    def serve(self, addr_str, fname='', format='svg'):
        if isinstance(addr_str, str):
            addr = int(addr_str, 16)
        elif isinstance(addr_str, int):
            addr = addr_str
        else:
            raise Exception('type error!')

        outfile = fname if fname else tempfile.mktemp(dir="/dev/shm/", prefix="cfg-explorer-")
        final_output = ''

        try:
            vis = self.create_vis(addr)
            self.annotate_vis(vis, addr)
            self.xref_vis(vis, addr)

            vis.set_output(DotOutput(outfile, format=format))
            self.process_vis(vis, addr)

            final_output = outfile + '.' + format

            if not fname:
                with open(final_output) as f:
                    return Response(f.read(), mimetype='image/svg+xml')
            else:
                l.info("CFG is exported to " + final_output)
        finally:
            if final_output and not fname and os.path.exists(final_output):
                os.remove(final_output)


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
