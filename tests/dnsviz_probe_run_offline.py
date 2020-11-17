import gzip
import io
import os
import subprocess
import tempfile
import unittest

DATA_DIR = os.path.dirname(__file__)
EXAMPLE_AUTHORITATIVE = os.path.join(DATA_DIR, 'data', 'example-authoritative.json.gz')
EXAMPLE_RECURSIVE = os.path.join(DATA_DIR, 'data', 'example-recursive.json.gz')
ROOT_AUTHORITATIVE = os.path.join(DATA_DIR, 'data', 'root-authoritative.json.gz')
ROOT_RECURSIVE = os.path.join(DATA_DIR, 'data', 'root-recursive.json.gz')
EXAMPLE_COM_SIGNED = os.path.join(DATA_DIR, 'zone', 'example.com.zone.signed')
EXAMPLE_COM_ZONE = os.path.join(DATA_DIR, 'zone', 'example.com.zone')
EXAMPLE_COM_DELEGATION = os.path.join(DATA_DIR, 'zone', 'example.com.zone-delegation')

class DNSProbeRunOfflineTestCase(unittest.TestCase):
    def setUp(self):
        self.current_cwd = os.getcwd()
        self.dnsviz_bin = os.path.join(self.current_cwd, 'bin', 'dnsviz')

        with gzip.open(EXAMPLE_AUTHORITATIVE, 'rb') as example_auth_in:
            with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as self.example_auth_out:
                self.example_auth_out.write(example_auth_in.read())

        with gzip.open(EXAMPLE_RECURSIVE, 'rb') as example_rec_in:
            with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as self.example_rec_out:
                self.example_rec_out.write(example_rec_in.read())

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as self.names_file:
            self.names_file.write('example.com\nexample.net\n'.encode('utf-8'))

        self.output = tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False)
        self.output.close()

        self.run_cwd = tempfile.mkdtemp(prefix='dnsviz')

    def tearDown(self):
        os.remove(self.example_auth_out.name)
        os.remove(self.example_rec_out.name)
        os.remove(self.names_file.name)
        os.remove(self.output.name)
        subprocess.check_call(['rm', '-rf', self.run_cwd])

    def test_dnsviz_probe_input(self):
        with io.open(self.output.name, 'wb') as fh_out:
            with gzip.open(EXAMPLE_AUTHORITATIVE) as fh_in:
                p = subprocess.Popen([self.dnsviz_bin, 'probe', '-d', '0', '-r', '-', 'example.com'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'probe', '-d', '0', '-r', self.example_auth_out.name, 'example.com'], stdout=fh), 0)

    def test_dnsviz_probe_names_input(self):
        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'probe', '-d', '0', '-r', self.example_auth_out.name, '-f', self.names_file.name], stdout=fh), 0)

        with io.open(self.output.name, 'wb') as fh_out:
            with io.open(self.names_file.name, 'rb') as fh_in:
                p = subprocess.Popen([self.dnsviz_bin, 'probe', '-d', '0', '-r', self.example_auth_out.name, '-f', '-'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

    def test_dnsviz_probe_output(self):
        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'probe', '-d', '0', '-r', self.example_auth_out.name, 'example.com'], cwd=self.run_cwd, stdout=fh), 0)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'probe', '-d', '0', '-r', self.example_auth_out.name, '-o', '-', 'example.com'], cwd=self.run_cwd, stdout=fh), 0)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'probe', '-d', '0', '-r', self.example_auth_out.name, '-o', 'all.json', 'example.com'], cwd=self.run_cwd, stdout=fh), 0)
            self.assertTrue(os.path.exists(os.path.join(self.run_cwd, 'all.json')))

    def test_dnsviz_probe_auth(self):
        with io.open(self.output.name, 'wb') as fh_out:
            with gzip.open(EXAMPLE_AUTHORITATIVE) as fh_in:
                p = subprocess.Popen([self.dnsviz_bin, 'probe', '-d', '0', '-r', '-', 'example.com'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

        with io.open(self.output.name, 'wb') as fh_out:
            with gzip.open(ROOT_AUTHORITATIVE) as fh_in:
                p = subprocess.Popen([self.dnsviz_bin, 'probe', '-d', '0', '-r', '-', '.'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

    def test_dnsviz_probe_rec(self):
        with io.open(self.output.name, 'wb') as fh_out:
            with gzip.open(EXAMPLE_RECURSIVE) as fh_in:
                p = subprocess.Popen([self.dnsviz_bin, 'probe', '-d', '0', '-r', '-', 'example.com'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

        with io.open(self.output.name, 'wb') as fh_out:
            with gzip.open(ROOT_RECURSIVE) as fh_in:
                p = subprocess.Popen([self.dnsviz_bin, 'probe', '-d', '0', '-r', '-', '.'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

    def test_dnsviz_probe_auth_local(self):
        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(
                [self.dnsviz_bin, 'probe', '-d', '0', '-A',
                    '-x' 'example.com:%s' % EXAMPLE_COM_SIGNED,
                    '-N' 'example.com:%s' % EXAMPLE_COM_DELEGATION,
                    '-D' 'example.com:%s' % EXAMPLE_COM_DELEGATION,
                    'example.com'], stdout=fh), 0)

if __name__ == '__main__':
    unittest.main()
