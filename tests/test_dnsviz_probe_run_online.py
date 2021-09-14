import io
import os
import subprocess
import tempfile
import unittest

class DNSVizProbeRunOnlineTestCase(unittest.TestCase):
    def setUp(self):
        self.current_cwd = os.getcwd()
        self.dnsviz_bin = os.path.join(self.current_cwd, 'bin', 'dnsviz')

        self.output = tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False)
        self.output.close()

    def tearDown(self):
        os.remove(self.output.name)

    def test_dnsviz_probe_auth(self):
        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'probe', '-d', '0', '-A', '.'], stdout=fh), 0)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'probe', '-d', '0', '-A', 'example.com'], stdout=fh), 0)

    def test_dnsviz_probe_rec(self):
        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'probe', '-d', '0', '.'], stdout=fh), 0)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'probe', '-d', '0', 'example.com'], stdout=fh), 0)

    def test_dnsviz_probe_rec_multi(self):
        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'probe', '-d', '0', '-t', '3', '.', 'example.com', 'example.net'], stdout=fh), 0)


if __name__ == '__main__':
    unittest.main()
