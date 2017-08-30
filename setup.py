from distutils.core import setup
try:
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    import os
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

setup(
    name='cfg-explorer',
    version='0.0.1',
    author='Attila Axt',
    author_email='axt@load.hu',
    license='BSD',
    platforms=['Linux'],
    packages=packages,
    install_requires=[
        'argparse',
        'angr',
        'bingraphvis'
    ],
    description='CFG explorer',
    long_description='CFG explorer',
    url='https://github.com/axt/cfg-explorer',
)
