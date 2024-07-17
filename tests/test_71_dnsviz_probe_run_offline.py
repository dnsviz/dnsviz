import io
import os
import subprocess
import tempfile
import unittest

from vars import *

class DNSProbeRunOfflineTestCase(unittest.TestCase):
    def setUp(self):
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
        os.remove(self.names_file.name)
        os.remove(self.output.name)
        subprocess.check_call(['rm', '-rf', self.run_cwd])

    def assertReturnCode(self, retcode):
        if retcode == 5:
            self.skipTest("No resolvers available")
        else:
            self.assertEqual(retcode, 0)

    def _probe_zone(self, subcat, signed):
        zone_file = get_zone_file(subcat, signed)
        delegation_file = get_delegation_file(subcat)
        output_file = get_probe_output_auth_file(subcat)

        cmd = ['dnsviz', 'probe', '-d', '0', '-A',
            '-x', '%s:%s' % (ZONE_ORIGIN, zone_file),
            '-N', '%s:%s' % (ZONE_ORIGIN, delegation_file)]

        if signed:
            cmd.extend(('-D', '%s:%s' % (ZONE_ORIGIN, delegation_file)))

        cmd.append(ZONE_ORIGIN)

        with io.open(output_file, 'wb') as fh:
            self.assertReturnCode(subprocess.call(cmd, stdout=fh))

    def test_dnsviz_probe_auth_local_signed_nsec(self):
        self._probe_zone('signed-nsec', True)

    def test_dnsviz_probe_auth_local_signed_nsec3(self):
        self._probe_zone('signed-nsec3', True)

    def test_dnsviz_probe_input(self):
        input_file = get_probe_output_auth_file('signed-nsec')

        with io.open(self.output.name, 'wb') as fh_out:
            with io.open(input_file, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'probe', '-d', '0', '-r', '-', ZONE_ORIGIN], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertReturnCode(p.returncode)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'probe', '-d', '0', '-r', input_file, ZONE_ORIGIN], stdout=fh), 0)

    def test_dnsviz_probe_names_input(self):
        input_file = get_probe_output_auth_file('signed-nsec')

        with io.open(self.output.name, 'wb') as fh:
            ret = subprocess.call(['dnsviz', 'probe', '-d', '0', '-r', input_file, '-f', self.names_file.name], stdout=fh)
            self.assertReturnCode(ret)

        with io.open(self.output.name, 'wb') as fh_out:
            with io.open(self.names_file.name, 'rb') as fh_in:
                p = subprocess.Popen(['dnsviz', 'probe', '-d', '0', '-r', input_file, '-f', '-'], stdin=subprocess.PIPE, stdout=fh_out)
                p.communicate(fh_in.read())
                self.assertEqual(p.returncode, 0)

    def test_dnsviz_probe_output(self):
        input_file = get_probe_output_auth_file('signed-nsec')

        with io.open(self.output.name, 'wb') as fh:
            ret = subprocess.call(['dnsviz', 'probe', '-d', '0', '-r', input_file, ZONE_ORIGIN], cwd=self.run_cwd, stdout=fh)
            self.assertReturnCode(ret)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'probe', '-d', '0', '-r', input_file, '-o', '-', ZONE_ORIGIN], cwd=self.run_cwd, stdout=fh), 0)

        with io.open(self.output.name, 'wb') as fh:
            self.assertEqual(subprocess.call(['dnsviz', 'probe', '-d', '0', '-r', input_file, '-o', 'all.json', ZONE_ORIGIN], cwd=self.run_cwd, stdout=fh), 0)
        self.assertTrue(os.path.exists(os.path.join(self.run_cwd, 'all.json')))

if __name__ == '__main__':
    unittest.main()
