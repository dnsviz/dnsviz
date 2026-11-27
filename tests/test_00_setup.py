import os
import subprocess
import unittest

from vars import *

class ZoneCreator:
    def __init__(self, unsigned_subcat):
        self.unsigned_subcat = unsigned_subcat
        self.unsigned_zone_dir = get_zone_dir(self.unsigned_subcat)
        self.unsigned_zone_file = get_zone_file('unsigned', False)

        self.keys = None
        self.skip_keys = os.getenv('DNSVIZ_KEYGEN_SKIP', '').split()

    def create_dir(self, mydir):
        if not os.path.exists(mydir):
            os.mkdir(mydir)

    def keygen(self, params):
        key_dir = get_key_dir()
        args = ['dnssec-keygen', '-q', '-K', key_dir]
        args.extend(params)
        args.append(ZONE_ORIGIN)
        return subprocess.check_output(args).decode('utf-8').strip()

    def add_key(self, algname, alg, bitsk=None, bitsz=None):
        if algname in self.skip_keys:
            return

        args = ['-f', 'KSK', '-a', alg]
        if bitsk is not None:
            args.extend(['-b', str(bitsk)])
        self.keys['KSK_'+algname] = \
                self.keygen(args)

        args = ['-a', alg]
        if bitsz is not None:
            args.extend(['-b', str(bitsz)])
        self.keys['ZSK_'+algname] = \
                self.keygen(args)

    def create_keys(self):
        self.keys = {}
        self.create_dir(get_key_dir())

        self.add_key('RSASHA1',   'RSASHA1',   2048, 1024)
        self.add_key('RSASHA256', 'RSASHA256', 2048, 1024)
        self.add_key('ECDSA256',  'ECDSAP256SHA256')
        self.add_key('ECDSA384',  'ECDSAP384SHA384')
        self.add_key('ED25519',   'ED25519')
        self.add_key('ED448',     'ED448')

    def get_key_file(self, key_type):
        return get_key_file(self.keys[key_type])

    def create_signed_zone(self, subcat, ksk, zsk, duplicate_suffix):
        zone_dir = get_zone_dir(subcat)
        self.create_dir(zone_dir)
        key_dir = get_key_dir()

        unsigned_zone_file = get_zone_file(subcat, False)
        unsigned_delegation_file = get_delegation_file(self.unsigned_subcat)
        delegation_file = get_delegation_file(subcat)

        ksk_file = self.get_key_file(ksk)
        zsk_file = self.get_key_file(zsk)
        tk_file = get_tk_file(subcat)

        with open(unsigned_zone_file, 'wb') as fh:
            subprocess.check_call(['cat', self.unsigned_zone_file, ksk_file, zsk_file], stdout=fh)

        subprocess.check_call(['dnssec-signzone', '-K', key_dir, '-x', '-k', self.keys[ksk], '-o', ZONE_ORIGIN, unsigned_zone_file, self.keys[zsk]])
        os.unlink('dsset-' + ZONE_ORIGIN + '.')
        with open(delegation_file, 'wb') as fh:
            subprocess.check_call(['cat', unsigned_delegation_file], stdout=fh)
            subprocess.check_call(['dnssec-dsfromkey', '-a', 'SHA-1', ksk_file], stdout=fh)
            subprocess.check_call(['dnssec-dsfromkey', '-a', 'SHA-256', ksk_file], stdout=fh)
            subprocess.check_call(['dnssec-dsfromkey', '-a', 'SHA-384', ksk_file], stdout=fh)

        if os.path.exists(tk_file):
            os.remove(tk_file)
        os.symlink(ksk_file, tk_file)

        if duplicate_suffix:
            duplicate_zone_dir = zone_dir + '-' + duplicate_suffix
            subprocess.check_call(['cp', '-pr', zone_dir, duplicate_zone_dir])

    def strip_rrsig(self, subcat, rrname, rdtype):
        rrname = rrname.rstrip('.')
        zone_file = get_zone_file(subcat, True)
        zone_contents_orig = subprocess.check_output(['named-checkzone', '-D', ZONE_ORIGIN, zone_file]).decode('utf-8')
        zone_contents_new = ''
        for line in zone_contents_orig.splitlines():
            try:
                myname, ttl, rdclass, mytype, covers, rest = line.split(maxsplit=5)
            except ValueError:
                pass
            else:
                if myname.rstrip('.') == rrname and mytype == 'RRSIG' and covers == rdtype:
                    continue
            zone_contents_new += '\n' + line
        with open(zone_file, 'w', encoding='utf-8') as fh:
            fh.write(zone_contents_new)

    def corrupt_sig(self, subcat, rrname, rdtype):
        rrname = rrname.rstrip('.')
        zone_file = get_zone_file(subcat, True)
        zone_contents_orig = subprocess.check_output(['named-checkzone', '-D', ZONE_ORIGIN, zone_file]).decode('utf-8')
        zone_contents_new = ''
        for line in zone_contents_orig.splitlines():
            try:
                myname, ttl, rdclass, mytype, covers, rest = line.split(maxsplit=5)
            except ValueError:
                pass
            else:
                replace_index = -6
                if myname.rstrip('.') == rrname and mytype == 'RRSIG' and covers == rdtype:
                    val = line[replace_index]
                    if val == 'A':
                        replacement = 'B'
                    else:
                        replacement = 'A'
                    line = line[:replace_index] + replacement + line[replace_index + 1:]
            zone_contents_new += '\n' + line
        with open(zone_file, 'w', encoding='utf-8') as fh:
            fh.write(zone_contents_new)

class TestSetup(unittest.TestCase):
    def test_setup(self):
        z = ZoneCreator('unsigned')
        z.create_keys()
        z.create_signed_zone('signed-nsec', 'KSK_RSASHA256', 'ZSK_RSASHA256', 'broken')
        z.create_signed_zone('signed-nsec3', 'KSK_RSASHA256', 'ZSK_RSASHA256', '')
        z.create_signed_zone('signed-nsec-alg15', 'KSK_ED25519', 'ZSK_ED25519', '')
        z.strip_rrsig('signed-nsec-broken', 'example.com', 'A')
        z.corrupt_sig('signed-nsec-broken', 'example.com', 'AAAA')

if __name__ == '__main__':
    unittest.main()
