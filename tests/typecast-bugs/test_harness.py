#!/usr/bin/env python

__author__ = 'bhargava'

import os, sys, subprocess
import collections
import filecmp
import unittest
import glob

statout = collections.namedtuple('StatusOutPair', ['ret', 'out'])


def execwrapper(args, errMsg):
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, executable="/bin/bash")
    out, err = p.communicate()
    if err:
        return statout(False, out)
    return statout(True, out)


def diffExp(filename, out):
    basename = os.path.basename(filename)
    with open("expects/%s.exp" % basename, "r") as expectation:
        expects = expectation.read()
        if out != expects:
            return False
    expectation.close()
    return True


def invokecj(filename):
    args = "clang --analyze -Xclang -load -Xclang /home/bhargava/work/gitlab/checkers/build-live/libusedef-checker.so -Xclang -analyzer-checker=alpha.security.CastChecker -Xanalyzer -analyzer-disable-checker=core,unix,deadcode,cplusplus,security %s" % filename
    retpair = execwrapper(args, "Test on %s" % filename + " failed")
    if retpair.ret:
        return diffExp(filename, retpair.out)
    return False


# Schema: filename, filename.nodes.exp, filename.edges.exp
def testinput(filename):
    return invokecj(filename)


class SimpleTester(unittest.TestCase):
    def tearDown(self):
        plist_files = glob.glob("*.plist")
        for f in plist_files:
            os.remove(f)


class TestBasic(SimpleTester):
    def test_malloc(self):
        self.assertEqual(testinput('malloc-int-unsigned.c'), True,
                         'Test on malloc-int-unsigned.c failed')
    def test_calloc(self):
        self.assertEqual(testinput('calloc-int-unsigned.c'), True,
                         'Test on calloc-int-unsigned.c failed')
    def test_realloc(self):
        self.assertEqual(testinput('realloc-int-unsigned.c'), True,
                         'Test on realloc-int-unsigned.c failed')
    def test_reallocarray(self):
        self.assertEqual(testinput('reallocarray-int-unsigned.c'), True,
                         'Test on reallocarray-int-unsigned.c failed')
    def test_memcpy(self):
        self.assertEqual(testinput('memcpy-int-unsigned.c'), True,
                         'Test on memcpy-int-unsigned.c failed')
    def test_memset(self):
        self.assertEqual(testinput('memset-int-unsigned.c'), True,
                         'Test on memset-int-unsigned.c failed')
    def test_memmove(self):
        self.assertEqual(testinput('memmove-int-unsigned.c'), True,
                         'Test on memmove-int-unsigned.c failed')
    def test_strncpy(self):
        self.assertEqual(testinput('strncpy-int-unsigned.c'), True,
                         'Test on strncpy-int-unsigned.c failed')
    def test_mallocimplicit(self):
        self.assertEqual(testinput('malloc-implicit.c'), True,
                         'Test on malloc-implicit.c failed')
    def test_callocimplicit(self):
        self.assertEqual(testinput('calloc-implicit.c'), True,
                         'Test on calloc-implicit.c failed')
    def test_reallocimplicit(self):
        self.assertEqual(testinput('realloc-implicit.c'), True,
                         'Test on realloc-implicit.c failed')
    def test_memcpyimplicit(self):
	self.assertEqual(testinput('memcpy-implicit.c'), True,
			'Test on memcpy-implicit.c failed')
    def test_memsetimplicit(self):
	self.assertEqual(testinput('memset-implicit.c'), True,
			'Test on memset-implicit.c failed')
    def test_memmoveimplicit(self):
        self.assertEqual(testinput('memmove-implicit.c'), True,
                         'Test on memmove-implicit.c failed')
    def test_strncpyimplicit(self):
        self.assertEqual(testinput('strncpy-implicit.c'), True,
                         'Test on strncpy-implicit.c failed')
    def test_range(self):
        self.assertEqual(testinput('rangetest.c'), True,
                         'Test on rangetest.c failed')


if __name__ == '__main__':
    unittest.main()
