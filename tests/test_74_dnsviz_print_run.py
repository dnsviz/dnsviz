import os
import re
import subprocess
import tempfile
import unittest

from vars import *

class DNSPrintRunTestCase(unittest.TestCase):
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

    def test_dnsviz_print_input(self):
        input_file = get_probe_output_auth_file('signed-nsec')

        with open(self.output.name, 'wb') as fh_out:
            with open(input_file, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'print'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

        with open(self.output.name, 'wb') as fh_out:
            with open(input_file, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'print', '-r', '-'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

        with open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'print', '-r', input_file], stdout=fh), 0)

    def test_dnsviz_print_names_input(self):
        input_file = get_probe_output_auth_file('signed-nsec')

        with open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'print', '-r', input_file, '-f', self.names_file.name], stdout=fh), 0)

        with open(self.output.name, 'wb') as fh_out:
            with open(self.names_file.name, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'print', '-r', input_file, '-f', '-'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

    def test_dnsviz_print_tk_input(self):
        input_file = get_probe_output_auth_file('signed-nsec')
        tk_file = get_tk_file('signed-nsec')

        with open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'print', '-r', input_file, '-t', tk_file], stdout=fh), 0)

        with open(self.output.name, 'wb') as fh_out:
            with open(tk_file, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'print', '-r', input_file, '-t', '-'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

    def test_dnsviz_print_output(self):
        input_file = get_probe_output_auth_file('signed-nsec')

        with open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'print', '-r', input_file], cwd=self.run_cwd, stdout=fh), 0)

        with open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'print', '-r', input_file, '-o', '-'], cwd=self.run_cwd, stdout=fh), 0)

        with open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'print', '-r', input_file, '-o', 'all.txt'], cwd=self.run_cwd, stdout=fh), 0)

        self.assertTrue(os.path.exists(os.path.join(self.run_cwd, 'all.txt')))
        self.assertFalse(os.path.exists(os.path.join(self.run_cwd, ZONE_ORIGIN + '.txt')))

        self.assertEqual(subprocess.call(['dnsviz', 'print', '-r', input_file, '-O'], cwd=self.run_cwd), 0)
        self.assertTrue(os.path.exists(os.path.join(self.run_cwd, ZONE_ORIGIN + '.txt')))

    def test_dnsviz_print_broken(self):
        input_file = get_probe_output_auth_file('signed-nsec-broken')

        contents = subprocess.check_output(['dnsviz', 'print', '-r', input_file]).decode('utf-8')

        NOTICE_RE = re.compile(r'^([IWE]):(\S+)')
        zone_origin = ZONE_ORIGIN.rstrip('.')

        found_rrsig = False
        found_rrset = False
        curr_domain_name = ''
        curr_rrtype = ''
        is_rrsig = False
        for line in contents.splitlines():
            if not line:
                continue

            if line[0] != ' ':
                curr_domain_name = line.split()[0]
                rrtype = ''
                rrsig = False
                continue

            parts = line.strip().split()
            if len(parts) < 2:
                continue

            m = NOTICE_RE.search(parts[1])
            if m is None:
                if not parts[1].startswith('RRSIG'):
                    rrtype = parts[1]
                    rrsig = False
                else:
                    rrsig = True
            else:
                # This is an answer for the current domain name and rrtype.

                category = m.group(1)
                if curr_domain_name == zone_origin and rrtype == 'A' and \
                        not rrsig and category == 'E':
                    code = m.group(2)
                    self.assertEqual(code, 'MISSING_RRSIG')

                elif curr_domain_name == zone_origin and rrtype == 'AAAA' and \
                        rrsig and category == 'E':
                    code = m.group(2)
                    self.assertEqual(code, 'SIGNATURE_INVALID')

if __name__ == '__main__':
    unittest.main()
