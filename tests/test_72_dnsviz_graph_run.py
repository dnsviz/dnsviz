import json
import os
import re
import subprocess
import tempfile
import unittest

from vars import *

class DNSGraphRunTestCase(unittest.TestCase):
    def setUp(self):
        self.devnull = open('/dev/null', 'wb')

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

    def test_dnsviz_graph_input(self):
        input_file = get_probe_output_auth_file('signed-nsec')

        with open(self.output.name, 'wb') as fh_out:
            with open(input_file, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'graph'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

        with open(self.output.name, 'wb') as fh_out:
            with open(input_file, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'graph', '-r', '-'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

        with open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'graph', '-r', input_file], stdout=fh), 0)

    def test_dnsviz_graph_names_input(self):
        input_file = get_probe_output_auth_file('signed-nsec')

        with open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'graph', '-r', input_file, '-f', self.names_file.name], stdout=fh), 0)

        with open(self.output.name, 'wb') as fh_out:
            with open(self.names_file.name, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'graph', '-r', input_file, '-f', '-'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

    def test_dnsviz_graph_tk_input(self):
        input_file = get_probe_output_auth_file('signed-nsec')
        tk_file = get_tk_file('signed-nsec')

        with open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'graph', '-r', input_file, '-t', tk_file], stdout=fh), 0)

        with open(self.output.name, 'wb') as fh_out:
            with open(tk_file, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'graph', '-r', input_file, '-t', '-'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

    def test_dnsviz_graph_output(self):
        input_file = get_probe_output_auth_file('signed-nsec')

        with open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'graph', '-r', input_file], cwd=self.run_cwd, stdout=fh), 0)

        with open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'graph', '-r', input_file, '-Tdot', '-o', '-'], cwd=self.run_cwd, stdout=fh), 0)

        with open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'graph', '-r', input_file, '-o', 'all.dot'], cwd=self.run_cwd, stdout=fh), 0)

        self.assertTrue(os.path.exists(os.path.join(self.run_cwd, 'all.dot')))
        self.assertFalse(os.path.exists(os.path.join(self.run_cwd, ZONE_ORIGIN + '.dot')))

        self.assertEqual(subprocess.call(['dnsviz', 'graph', '-r', input_file, '-O'], cwd=self.run_cwd), 0)
        self.assertTrue(os.path.exists(os.path.join(self.run_cwd, ZONE_ORIGIN + '.dot')))

    def test_dnsviz_graph_output_format(self):
        input_file = get_probe_output_auth_file('signed-nsec')

        magic_codes_mapping = {
                'dot': b'digraph',
                'png': b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
                'svg': b'<?xml ',
                'html': b'<?xml ',
            }

        for fmt in ('dot', 'png', 'svg', 'html'):
            with open(self.output.name, 'wb') as fh:
                self.assertEqual(subprocess.call(['dnsviz', 'graph', '-r', input_file, '-o', 'all.'+fmt], cwd=self.run_cwd, stdout=fh), 0)
                self.assertTrue(os.path.exists(os.path.join(self.run_cwd, 'all.'+fmt)))
                self.assertFalse(os.path.exists(os.path.join(self.run_cwd, ZONE_ORIGIN + '.' + fmt)))

                with open(os.path.join(self.run_cwd, 'all.' + fmt), 'rb') as fh:
                    first_bytes = fh.read(len(magic_codes_mapping[fmt]))
                    self.assertEqual(first_bytes, magic_codes_mapping[fmt])

            self.assertEqual(subprocess.call(['dnsviz', 'graph', '-r', input_file, '-T', fmt, '-O'], cwd=self.run_cwd), 0)
            self.assertTrue(os.path.exists(os.path.join(self.run_cwd, ZONE_ORIGIN + '.' + fmt)))

            with open(os.path.join(self.run_cwd, ZONE_ORIGIN + '.' + fmt), 'rb') as fh:
                first_bytes = fh.read(len(magic_codes_mapping[fmt]))
                self.assertEqual(first_bytes, magic_codes_mapping[fmt])

    def test_dnsviz_graph_broken(self):
        input_file = get_probe_output_auth_file('signed-nsec-broken')

        contents = subprocess.check_output(['dnsviz', 'graph', '-r', input_file, '-Thtml']).decode('utf-8')

        RRSIG_COLOR = 'be1515'
        RRSIG_STYLE = 'solid'
        zone_origin = ZONE_ORIGIN.rstrip('.')
        RRSET_OBJ_RE = re.compile(r'^RRset-\d+\|' + zone_origin + r'\|A$')
        RRSIG_OBJ_RE = re.compile(r'^RRSIG-RRset-\d+\|' + zone_origin + \
                r'\|AAAA\|DNSKEY-\d+\|' + zone_origin + r'\|\d+\|\d+\|' + \
                RRSIG_COLOR + r'\|' + RRSIG_STYLE + r'$')

        obj = None
        for line in contents.splitlines():
            if line.startswith('\tvar node_info = '):
                line = line[17:-1]
                obj = json.loads(line)

        self.assertIsNotNone(obj)

        found_rrsig = False
        found_rrset = False
        for item in obj:
            m = RRSET_OBJ_RE.search(item)
            if m is not None:
                found_rrset = True
                rrset = obj[item][0]
                err = rrset['errors'][0]
                code = err['code']
                server = err['servers'][0]
                self.assertEqual(code, 'MISSING_RRSIG')
                self.assertIn(server, ('127.0.0.1', '::1'))

            m = RRSIG_OBJ_RE.search(item)
            if m is not None:
                found_rrsig = True
                rrsig = obj[item][0]
                status = rrsig['status']
                err = rrsig['errors'][0]
                code = err['code']
                self.assertEqual(status, 'INVALID_SIG')
                self.assertEqual(code, 'SIGNATURE_INVALID')

        self.assertTrue(found_rrsig)
        self.assertTrue(found_rrset)

if __name__ == '__main__':
    unittest.main()
