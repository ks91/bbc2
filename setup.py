import subprocess
import sys, os, shutil, site
from os import path
from setuptools import setup
from setuptools.command.install import install

VERSION = "0.2.1"

here = path.abspath(path.dirname(__file__))

with open('README.rst') as f:
    readme = f.read()


class MyInstall(install):
    def run(self):
        try:
            install.run(self)
        except Exception as e:
            print(e)
            exit(1)


class VerifyVersionCommand(install):
    """Custom command to verify that the git tag matches our version"""
    description = 'verify that the git tag matches our version'

    def run(self):
        tag = os.getenv('CIRCLE_TAG')

        if tag != "v%s" % VERSION:
            info = "Git tag: {0} does not match the version of this app: {1}".format(
                tag, "v%s" % VERSION
            )
            sys.exit(info)


bbc2_requires = [
                 'pyOpenSSL>=16.2.0',
                 'jinja2>=2.8.1',
                 'requests>=2.12.4',
                 'gevent>=1.2.1',
                 'cryptography>=2.1.4',
                 'pytest>=5.3.0',
                 'msgpack-python>=0.4.8',
                 'mysql-connector-python>=8.0.5',
                 'py-bbclib>=1.6',
                 'greenlet',
                 'bson',
                 'Flask',
                 'eth-brownie>=1.19.3'
                ]

bbc2_packages = [
                 'bbc2',
                 'bbc2.lib',
                 'bbc2.serv',
                 'bbc2.serv.api',
                 'bbc2.serv.ethereum'
                ]

bbc2_commands = [
                 'bbc2/serv/bbc_serv.py',
                 'utils/bbc_eth_tool.py',
                ]

bbc2_classifiers = [
                    'Development Status :: 2 - Pre-Alpha',
                    'Programming Language :: Python :: 3.9',
                    'Topic :: Software Development']

setup(
    name='bbc2',
    version=VERSION,
    description='Beyond Blockchain Two ledger system',
    long_description_content_type='text/markdown',
    long_description=readme,
    url='https://github.com/beyond-blockchain/bbc2',
    author='beyond-blockchain.org',
    author_email='bbc1-dev@beyond-blockchain.org',
    license='Apache License 2.0',
    classifiers=bbc2_classifiers,
    cmdclass={'install': MyInstall, 'verify': VerifyVersionCommand},
    packages=bbc2_packages,
    scripts=bbc2_commands,
    install_requires=bbc2_requires,
    include_package_data=True,
    zip_safe=False)

# end of setup.py
