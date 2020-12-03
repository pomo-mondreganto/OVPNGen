import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESOURCES = os.path.join(BASE_DIR, 'resources')
RESULT_DIR = os.path.join(BASE_DIR, 'result')
TEMPLATES_PATH = os.path.join(BASE_DIR, 'templates')

SERVER_CONFIG_DIR = os.path.join(RESULT_DIR, 'server')
TEAM_CLIENT_DIR = os.path.join(RESULT_DIR, 'team')
VULN_CLIENT_DIR = os.path.join(RESULT_DIR, 'vuln')
JURY_CLIENT_DIR = os.path.join(RESULT_DIR, 'jury')

TEAM_SERVER_DIR = os.path.join(SERVER_CONFIG_DIR, 'team')
VULN_SERVER_DIR = os.path.join(SERVER_CONFIG_DIR, 'vuln')
JURY_SERVER_DIR = os.path.join(SERVER_CONFIG_DIR, 'jury')

TEAM_PORT = 31000
VULN_PORT = 32000
JURY_PORT = 33000

PROTOCOL = 'udp'
