import os

BASE_DIR = os.path.dirname(__file__)

ZONE_ORIGIN = 'example.com'
ZONE_DIR = 'zones'
KEY_DIR = 'keys'
ZONE_FILE = ZONE_ORIGIN + '.zone'
ZONE_FILE_SIGNED = ZONE_FILE + '.signed'
ZONE_FILE_DELEGATION = ZONE_FILE + '-delegation'
PROBE_AUTH_OUTPUT = ZONE_ORIGIN + '-probe-auth.json'
PROBE_REC_OUTPUT = ZONE_ORIGIN + '-probe-rec.json'
TK_FILE = 'tk.txt'

def get_zone_dir(subcat):
    return os.path.join(BASE_DIR, ZONE_DIR, subcat)

def get_key_dir():
    return os.path.join(BASE_DIR, KEY_DIR)

def get_zone_file(subcat, signed):
    if signed:
        zone_file = ZONE_FILE_SIGNED
    else:
        zone_file = ZONE_FILE
    zone_file_dir = get_zone_dir(subcat)
    return os.path.join(zone_file_dir, zone_file)

def get_tk_file(subcat):
    zone_file_dir = get_zone_dir(subcat)
    return os.path.join(zone_file_dir, TK_FILE)

def get_delegation_file(subcat):
    zone_file_dir = get_zone_dir(subcat)
    return os.path.join(zone_file_dir, ZONE_FILE_DELEGATION)

def get_key_file(key_name):
    key_dir = get_key_dir()
    return os.path.join(key_dir, key_name + '.key')

def get_probe_output_auth_file(subcat):
    zone_file_dir = get_zone_dir(subcat)
    return os.path.join(zone_file_dir, PROBE_AUTH_OUTPUT)

def get_probe_output_rec_file(subcat):
    zone_file_dir = get_zone_dir(subcat)
    return os.path.join(zone_file_dir, PROBE_REC_OUTPUT)
