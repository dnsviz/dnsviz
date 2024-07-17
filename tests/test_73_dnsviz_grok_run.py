import io
import os
import subprocess
import tempfile
import unittest

from vars import *

class DNSGrokRunTestCase(unittest.TestCase):
    def setUp(self):
        self.devnull = io.open('/dev/null', 'wb')

        #TODO
        #with gzip.open(EXAMPLE_RECURSIVE, 'rb') as example_rec_in:
        #    with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as self.example_rec_out:
        #        self.example_rec_out.write(example_rec_in.read())

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as self.names_file:
            self.names_file.write((ZONE_ORIGIN + '\n').encode('utf-8'))

        self.output = tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False)
        self.output.close()

        self.run_cwd = tempfile.mkdtemp(prefix='dnsviz')

    def tearDown(self):
        self.devnull.close()
        os.remove(self.names_file.name)
        os.remove(self.output.name)
        subprocess.check_call(['rm', '-rf', self.run_cwd])

    def test_dnsviz_grok_input(self):
        input_file = get_probe_output_auth_file('signed-nsec')

        with io.open(self.output.name, 'wb') as fh_out:
            with io.open(input_file, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'grok'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

        with io.open(self.output.name, 'wb') as fh_out:
            with io.open(input_file, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'grok', '-r', '-'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'grok', '-r', input_file], stdout=fh), 0)

    def test_dnsviz_grok_names_input(self):
        input_file = get_probe_output_auth_file('signed-nsec')

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'grok', '-r', input_file, '-f', self.names_file.name], stdout=fh), 0)

        with io.open(self.output.name, 'wb') as fh_out:
            with io.open(self.names_file.name, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'grok', '-r', input_file, '-f', '-'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

    def test_dnsviz_grok_tk_input(self):
        input_file = get_probe_output_auth_file('signed-nsec')
        tk_file = get_tk_file('signed-nsec')

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'grok', '-r', input_file, '-t', tk_file], stdout=fh), 0)

        with io.open(self.output.name, 'wb') as fh_out:
            with io.open(tk_file, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'grok', '-r', input_file, '-t', '-'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

    def test_dnsviz_grok_output(self):
        input_file = get_probe_output_auth_file('signed-nsec')

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'grok', '-r', input_file], cwd=self.run_cwd, stdout=fh), 0)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'grok', '-r', input_file, '-o', '-'], cwd=self.run_cwd, stdout=fh), 0)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'grok', '-r', input_file, '-o', 'all.json'], cwd=self.run_cwd, stdout=fh), 0)

        self.assertTrue(os.path.exists(os.path.join(self.run_cwd, 'all.json')))

if __name__ == '__main__':
    unittest.main()
