import io
import os
import subprocess
import unittest

DATA_DIR = os.path.dirname(__file__)
EXAMPLE_COM_SIGNED = os.path.join(DATA_DIR, 'zone', 'example.com.zone.signed')
EXAMPLE_COM_ZONE = os.path.join(DATA_DIR, 'zone', 'example.com.zone')
EXAMPLE_COM_DELEGATION = os.path.join(DATA_DIR, 'zone', 'example.com.zone-delegation')

class DNSProbeTestCase(unittest.TestCase):
    def setUp(self):
        self.devnull = io.open('/dev/null', 'wb')

    def tearDown(self):
        self.devnull.close()

    def test_authoritative_probe_root(self):
        self.assertEqual(subprocess.call(
            ['dnsviz', 'probe', '-d', '0', '-A',
                '-x' 'example.com:%s' % EXAMPLE_COM_SIGNED,
                '-N' 'example.com:%s' % EXAMPLE_COM_DELEGATION,
                '-D' 'example.com:%s' % EXAMPLE_COM_DELEGATION,
                'example.com'], stdout=self.devnull), 0)

if __name__ == '__main__':
    unittest.main()
