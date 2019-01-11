import gzip
import io
import os
import subprocess
import unittest

class DNSProbeTestCase(unittest.TestCase):
    def setUp(self):
        self.devnull = io.open('/dev/null', 'wb')

    def tearDown(self):
        self.devnull.close()

    def test_authoritative_probe_root(self):
        self.assertEqual(subprocess.call(['dnsviz', 'probe', '-d', '0', '-A', '.'], stdout=self.devnull), 0)

    def test_authoritative_probe_example_com(self):
        self.assertEqual(subprocess.call(['dnsviz', 'probe', '-d', '0', '-A', 'example.com'], stdout=self.devnull), 0)

    def test_recursive_probe_root(self):
        self.assertEqual(subprocess.call(['dnsviz', 'probe', '-d', '0', '.'], stdout=self.devnull), 0)

    def test_recursive_probe_example_com(self):
        self.assertEqual(subprocess.call(['dnsviz', 'probe', '-d', '0', 'example.com'], stdout=self.devnull), 0)

class DNSGrokTestCase(unittest.TestCase):
    def setUp(self):
        self.devnull = io.open('/dev/null', 'wb')

    def tearDown(self):
        self.devnull.close()

    def test_grok_root_authoritative(self):
        with gzip.open('%s/data/root-authoritative.json.gz' % os.path.dirname(__file__)) as fh:
            p = subprocess.Popen(['dnsviz', 'grok'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_grok_root_recursive(self):
        with gzip.open('%s/data/root-recursive.json.gz' % os.path.dirname(__file__)) as fh:
            p = subprocess.Popen(['dnsviz', 'grok'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_grok_example_authoritative(self):
        with gzip.open('%s/data/example-authoritative.json.gz' % os.path.dirname(__file__)) as fh:
            p = subprocess.Popen(['dnsviz', 'grok'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_grok_example_recursive(self):
        with gzip.open('%s/data/example-recursive.json.gz' % os.path.dirname(__file__)) as fh:
            p = subprocess.Popen(['dnsviz', 'grok'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

class DNSPrintTestCase(unittest.TestCase):
    def setUp(self):
        self.devnull = io.open('/dev/null', 'wb')

    def tearDown(self):
        self.devnull.close()

    def test_print_root_authoritative(self):
        with gzip.open('%s/data/root-authoritative.json.gz' % os.path.dirname(__file__)) as fh:
            p = subprocess.Popen(['dnsviz', 'print'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_print_root_recursive(self):
        with gzip.open('%s/data/root-recursive.json.gz' % os.path.dirname(__file__)) as fh:
            p = subprocess.Popen(['dnsviz', 'print'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_print_example_authoritative(self):
        with gzip.open('%s/data/example-authoritative.json.gz' % os.path.dirname(__file__)) as fh:
            p = subprocess.Popen(['dnsviz', 'print'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_print_example_recursive(self):
        with gzip.open('%s/data/example-recursive.json.gz' % os.path.dirname(__file__)) as fh:
            p = subprocess.Popen(['dnsviz', 'print'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

class DNSGraphTestCase(unittest.TestCase):
    def setUp(self):
        self.devnull = io.open('/dev/null', 'wb')

    def tearDown(self):
        self.devnull.close()

    def test_graph_root_authoritative(self):
        with gzip.open('%s/data/root-authoritative.json.gz' % os.path.dirname(__file__)) as fh:
            p = subprocess.Popen(['dnsviz', 'graph', '-Thtml'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_graph_root_recursive(self):
        with gzip.open('%s/data/root-recursive.json.gz' % os.path.dirname(__file__)) as fh:
            p = subprocess.Popen(['dnsviz', 'graph', '-Thtml'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_graph_example_authoritative(self):
        with gzip.open('%s/data/example-authoritative.json.gz' % os.path.dirname(__file__)) as fh:
            p = subprocess.Popen(['dnsviz', 'graph', '-Thtml'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

    def test_graph_example_recursive(self):
        with gzip.open('%s/data/example-recursive.json.gz' % os.path.dirname(__file__)) as fh:
            p = subprocess.Popen(['dnsviz', 'graph', '-Thtml'], stdin=subprocess.PIPE, stdout=self.devnull)
            p.communicate(input=fh.read())
            self.assertEqual(p.returncode, 0)

if __name__ == '__main__':
    unittest.main()
