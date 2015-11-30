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
    args = "clang --analyze -Xclang -load -Xclang /home/bhargava/work/gitlab/checkers/build-live/libusedef-checker.so -Xclang -analyzer-checker=alpha.security.PHPChecker -Xanalyzer -analyzer-disable-checker=core,unix,deadcode,cplusplus,security %s" % filename
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
    def test_unsanstr(self):
        self.assertEqual(testinput('test-unsanstr.c'), True,
                         'Test on test-unsanstr.c failed')
    def test_sancall(self):
        self.assertEqual(testinput('test-sancall.c'), True,
                         'Test on test-sancall.c failed')

if __name__ == '__main__':
    unittest.main()
