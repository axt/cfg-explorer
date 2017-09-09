from bingraphvis.base import NodeAnnotator

class XRefFunctions(NodeAnnotator):
    def __init__(self, name):
        super(XRefFunctions, self).__init__()
        self.name = name

    def annotate_node(self, node):
        if type(node.obj).__name__ == 'Function':
            node.url = '/api/%s/%#x' % (self.name, node.obj.addr)
            node.tooltip = 'Click to navigate to function %#x' % node.obj.addr

class XRefCFGCallsites(NodeAnnotator):
    def __init__(self, project, name):
        super(XRefCFGCallsites, self).__init__()
        self.project = project
        self.name = name

    def annotate_node(self, node):
        func = self.project.kb.functions[node.obj.function_address]
        if node.obj.addr in func.get_call_sites():
            target = func.get_call_target(node.obj.addr)
            node.url = '/api/%s/%#x' % (self.name, target)
            node.tooltip = 'Click to navigate to function %#x' % target

