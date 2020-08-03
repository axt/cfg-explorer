from setuptools import setup, find_packages

try:
    packages = find_packages()
except ImportError:
    import os
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='cfg-explorer',
    version='0.0.1',
    author='Attila Axt',
    author_email='axt@load.hu',
    packages=packages,
    include_package_data=True,
    install_requires=['argparse', 'angr', 'bingraphvis', 'flask'],
    entry_points={
        'console_scripts': ['cfgexplorer=cfgexplorer.__main__:main'],
    },
    description='CFG explorer',
    classifiers=[
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        "Operating System :: POSIX :: Linux",
        "License :: OSI Approved :: BSD License"
    ],
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/axt/cfg-explorer',
)
