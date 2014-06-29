try:
    from setuptools import setup

except:
    from distutils.core import setup
import sys
from setuptools.command.test import test as TestCommand

try:
    from pypandoc import convert
    read_md = lambda f: convert(f, 'rst')
except ImportError:
    print("warning: pypandoc module not found, could not convert Markdown to RST")
    read_md = lambda f: open(f, 'r').read()

class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)


setup(
    name='snortsig',
    version='0.1',
    requires=['pyparsing'],
    tests_require = ["requests"],
    cmdclass = {'test': PyTest},
    url='http://www.github.com/Phillipmartin/snortsig',
    license='MIT',
    author='Philip Martin',
    author_email='phillip.martin@gmail.com',
    description='A module to simplify working with Snort signatures',
    py_modules   = ["snortsig"],
    long_description=read_md('README.md'),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],

)
