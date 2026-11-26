import shutil
import unittest

from vars import *

class TestSetup(unittest.TestCase):
    def test_setup(self):
        shutil.rmtree(get_key_dir())
        shutil.rmtree(get_zone_dir('signed-nsec'))
        shutil.rmtree(get_zone_dir('signed-nsec3'))
        shutil.rmtree(get_zone_dir('signed-nsec-alg15'))
        shutil.rmtree(get_zone_dir('signed-nsec-broken'))

if __name__ == '__main__':
    unittest.main()
