import io
import subprocess
import unittest

class DNSProbeTestCase(unittest.TestCase):
    def setUp(self):
        self.devnull = io.open('/dev/null', 'wb')

    def tearDown(self):
        self.devnull.close()

    def test_authoritative_probe_root(self):
        self.assertEqual(subprocess.call(['./bin/dnsviz', 'probe', '-d', '0', '-A', '.'], stdout=self.devnull), 0)

    def test_authoritative_probe_example_com(self):
        self.assertEqual(subprocess.call(['./bin/dnsviz', 'probe', '-d', '0', '-A', 'example.com'], stdout=self.devnull), 0)

    def test_recursive_probe_root(self):
        self.assertEqual(subprocess.call(['./bin/dnsviz', 'probe', '-d', '0', '.'], stdout=self.devnull), 0)

    def test_recursive_probe_example_com(self):
        self.assertEqual(subprocess.call(['./bin/dnsviz', 'probe', '-d', '0', 'example.com'], stdout=self.devnull), 0)

if __name__ == '__main__':
    unittest.main()
