import gzip
import io
import os
import subprocess
import unittest

DATA_DIR = os.path.dirname(__file__)
EXAMPLE_AUTHORITATIVE = os.path.join(DATA_DIR, 'data', 'example-authoritative.json.gz')
EXAMPLE_RECURSIVE = os.path.join(DATA_DIR, 'data', 'example-recursive.json.gz')
ROOT_AUTHORITATIVE = os.path.join(DATA_DIR, 'data', 'root-authoritative.json.gz')
ROOT_RECURSIVE = os.path.join(DATA_DIR, 'data', 'root-recursive.json.gz')

class DNSGrokTestCase(unittest.TestCase):
    def setUp(self):
        self.devnull = io.open('/dev/null', 'wb')

    def tearDown(self):
        self.devnull.close()

    def test_grok_root_authoritative(self):
        with gzip.open(ROOT_AUTHORITATIVE) as fh:
            p = subprocess.Popen(['dnsviz', 'grok'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_grok_root_recursive(self):
        with gzip.open(ROOT_RECURSIVE) as fh:
            p = subprocess.Popen(['dnsviz', 'grok'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_grok_example_authoritative(self):
        with gzip.open(EXAMPLE_AUTHORITATIVE) as fh:
            p = subprocess.Popen(['dnsviz', 'grok'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_grok_example_recursive(self):
        with gzip.open(EXAMPLE_RECURSIVE) as fh:
            p = subprocess.Popen(['dnsviz', 'grok'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

class DNSPrintTestCase(unittest.TestCase):
    def setUp(self):
        self.devnull = io.open('/dev/null', 'wb')

    def tearDown(self):
        self.devnull.close()

    def test_print_root_authoritative(self):
        with gzip.open(ROOT_AUTHORITATIVE) as fh:
            p = subprocess.Popen(['dnsviz', 'print'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_print_root_recursive(self):
        with gzip.open(ROOT_RECURSIVE) as fh:
            p = subprocess.Popen(['dnsviz', 'print'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_print_example_authoritative(self):
        with gzip.open(EXAMPLE_AUTHORITATIVE) as fh:
            p = subprocess.Popen(['dnsviz', 'print'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_print_example_recursive(self):
        with gzip.open(EXAMPLE_RECURSIVE) as fh:
            p = subprocess.Popen(['dnsviz', 'print'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

class DNSGraphTestCase(unittest.TestCase):
    def setUp(self):
        self.devnull = io.open('/dev/null', 'wb')

    def tearDown(self):
        self.devnull.close()

    def test_graph_root_authoritative(self):
        with gzip.open(ROOT_AUTHORITATIVE) as fh:
            p = subprocess.Popen(['dnsviz', 'graph', '-Thtml'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_graph_root_recursive(self):
        with gzip.open(ROOT_RECURSIVE) as fh:
            p = subprocess.Popen(['dnsviz', 'graph', '-Thtml'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_graph_example_authoritative(self):
        with gzip.open(EXAMPLE_AUTHORITATIVE) as fh:
            p = subprocess.Popen(['dnsviz', 'graph', '-Thtml'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_graph_example_recursive(self):
        with gzip.open(EXAMPLE_RECURSIVE) as fh:
            p = subprocess.Popen(['dnsviz', 'graph', '-Thtml'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

if __name__ == '__main__':
    unittest.main()
