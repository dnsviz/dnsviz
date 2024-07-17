import io
import os
import platform
import subprocess
import tempfile
import unittest

class DNSVizProbeRunOnlineTestCase(unittest.TestCase):
    def setUp(self):
        self.current_cwd = os.getcwd()

        self.output = tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False)
        self.output.close()

    def tearDown(self):
        os.remove(self.output.name)

    def assertReturnCode(self, retcode):
        if retcode == 5:
            self.skipTest("No recursive resolves found nor given")
        else:
            self.assertEqual(retcode, 0)

    def test_dnsviz_probe_auth(self):
        with io.open(self.output.name, 'wb') as fh:
            self.assertReturnCode(subprocess.call(['dnsviz', 'probe', '-d', '0', '-A', '.'], stdout=fh))

        with io.open(self.output.name, 'wb') as fh:
            self.assertReturnCode(subprocess.call(['dnsviz', 'probe', '-d', '0', '-A', 'example.com'], stdout=fh))

    def test_dnsviz_probe_rec(self):
        with io.open(self.output.name, 'wb') as fh:
            self.assertReturnCode(subprocess.call(['dnsviz', 'probe', '-d', '0', '.'], stdout=fh))

        with io.open(self.output.name, 'wb') as fh:
            self.assertReturnCode(subprocess.call(['dnsviz', 'probe', '-d', '0', 'example.com'], stdout=fh))

    def test_dnsviz_probe_rec_multi(self):
        if platform.system().lower() == 'darwin':
            # Skip MacOS
            return
        with io.open(self.output.name, 'wb') as fh:
            self.assertReturnCode(subprocess.call(['dnsviz', 'probe', '-d', '0', '-t', '3', '.', 'example.com', 'example.net'], stdout=fh))

if __name__ == '__main__':
    unittest.main()
