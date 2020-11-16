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

class DNSGraphRunTestCase(unittest.TestCase):
    def setUp(self):
        self.devnull = io.open('/dev/null', 'wb')
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
        self.devnull.close()
        os.remove(self.example_auth_out.name)
        os.remove(self.example_rec_out.name)
        os.remove(self.names_file.name)
        os.remove(self.output.name)
        subprocess.check_call(['rm', '-rf', self.run_cwd])

    def test_dnsviz_graph_input(self):
        with io.open(self.output.name, 'wb') as fh_out:
            with gzip.open(EXAMPLE_AUTHORITATIVE) as fh_in:
                p = subprocess.Popen([self.dnsviz_bin, 'graph'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

        with io.open(self.output.name, 'wb') as fh_out:
            with gzip.open(EXAMPLE_AUTHORITATIVE) as fh_in:
                p = subprocess.Popen([self.dnsviz_bin, 'graph', '-r', '-'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'graph', '-r', self.example_auth_out.name], stdout=fh), 0)

    def test_dnsviz_graph_names_input(self):
        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'graph', '-r', self.example_auth_out.name, '-f', self.names_file.name], stdout=fh), 0)

        with io.open(self.output.name, 'wb') as fh_out:
            with io.open(self.names_file.name, 'rb') as fh_in:
                p = subprocess.Popen([self.dnsviz_bin, 'graph', '-r', self.example_auth_out.name, '-f', '-'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

    def test_dnsviz_graph_output(self):
        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'graph', '-r', self.example_auth_out.name], cwd=self.run_cwd, stdout=fh), 0)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'graph', '-r', self.example_auth_out.name, '-Tdot', '-o', '-'], cwd=self.run_cwd, stdout=fh), 0)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call([self.dnsviz_bin, 'graph', '-r', self.example_auth_out.name, '-o', 'all.dot'], cwd=self.run_cwd, stdout=fh), 0)
            self.assertTrue(os.path.exists(os.path.join(self.run_cwd, 'all.dot')))
            self.assertFalse(os.path.exists(os.path.join(self.run_cwd, 'example.com.dot')))
            self.assertFalse(os.path.exists(os.path.join(self.run_cwd, 'example.net.dot')))

        self.assertEqual(subprocess.call([self.dnsviz_bin, 'graph', '-r', self.example_auth_out.name, '-O'], cwd=self.run_cwd), 0)
        self.assertTrue(os.path.exists(os.path.join(self.run_cwd, 'example.com.dot')))
        self.assertTrue(os.path.exists(os.path.join(self.run_cwd, 'example.net.dot')))

    def test_dnsviz_graph_input_auth(self):
        with io.open(self.output.name, 'wb') as fh_out:
            with gzip.open(EXAMPLE_AUTHORITATIVE) as fh_in:
                p = subprocess.Popen([self.dnsviz_bin, 'graph'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

        with io.open(self.output.name, 'wb') as fh_out:
            with gzip.open(ROOT_AUTHORITATIVE) as fh_in:
                p = subprocess.Popen([self.dnsviz_bin, 'graph'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

    def test_dnsviz_graph_input_rec(self):
        with io.open(self.output.name, 'wb') as fh_out:
            with gzip.open(EXAMPLE_RECURSIVE) as fh_in:
                p = subprocess.Popen([self.dnsviz_bin, 'graph'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

        with io.open(self.output.name, 'wb') as fh_out:
            with gzip.open(ROOT_RECURSIVE) as fh_in:
                p = subprocess.Popen([self.dnsviz_bin, 'graph'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

    def test_dnsviz_graph_output_format(self):
        for fmt in ('dot', 'png', 'svg', 'html'):
            with io.open(self.output.name, 'wb') as fh:
                self.assertEqual(subprocess.call([self.dnsviz_bin, 'graph', '-r', self.example_auth_out.name, '-T', fmt, '-o', 'all.'+fmt], cwd=self.run_cwd, stdout=fh), 0)
                self.assertTrue(os.path.exists(os.path.join(self.run_cwd, 'all.dot')))
                self.assertFalse(os.path.exists(os.path.join(self.run_cwd, 'example.com.' + fmt)))
                self.assertFalse(os.path.exists(os.path.join(self.run_cwd, 'example.net.' + fmt)))

            self.assertEqual(subprocess.call([self.dnsviz_bin, 'graph', '-r', self.example_auth_out.name, '-T', fmt, '-O'], cwd=self.run_cwd), 0)
            self.assertTrue(os.path.exists(os.path.join(self.run_cwd, 'example.com.' + fmt)))
            self.assertTrue(os.path.exists(os.path.join(self.run_cwd, 'example.net.' + fmt)))

if __name__ == '__main__':
    unittest.main()
