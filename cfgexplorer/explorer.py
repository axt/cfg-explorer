import logging
l = logging.getLogger('axt.cfgexplorer')

import os
from flask import Flask, send_from_directory
        
class CFGExplorer(object):
    def __init__(self, port=5000):
        
        self._static_files_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../static/")
        self._app = Flask(__name__)

        self._app.add_url_rule('/<path:file_relative_path_to_root>', 'serve_page', self._serve_page, methods=['GET'])
        self._app.add_url_rule('/', 'index', self._goto_index, methods=['GET'])

        self.port = port

    def add_vis_endpoint(self, endpoint):
        self._app.add_url_rule('/api/%s/<string:addr_str>' % endpoint.name, endpoint.name, endpoint.serve, methods=['GET'])
        
    def _goto_index(self):
        return self._serve_page("index.html")

    def _serve_page(self, file_relative_path_to_root):
        return send_from_directory(self._static_files_root, file_relative_path_to_root)

    def run(self):
        self._app.run(debug=True, use_reloader=False, port=self.port)
