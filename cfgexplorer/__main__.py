import logging
logging.getLogger('axt.cfgexplorer').setLevel(logging.INFO)

from . import CFGExplorerCLI

def main():
    explorer = CFGExplorerCLI()
    explorer.run()

if __name__ == '__main__':
    main()
