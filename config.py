import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESOURCES = os.path.join(BASE_DIR, 'resources')
RESULT_DIR = os.path.join(BASE_DIR, 'result')

SERVER_CONFIG_DIR = os.path.join(RESULT_DIR, 'server')
CLIENT_CONFIG_DIR = os.path.join(RESULT_DIR, 'client')
VULNBOX_CONFIG_DIR = os.path.join(RESULT_DIR, 'vulnbox')
JURY_CONFIG_DIR = os.path.join(RESULT_DIR, 'jury')

CLIENT_SERVER_CONFIG_DIR = os.path.join(SERVER_CONFIG_DIR, 'client')
VULNBOX_SERVER_CONFIG_DIR = os.path.join(SERVER_CONFIG_DIR, 'vulnbox')
JURY_SERVER_CONFIG_DIR = os.path.join(SERVER_CONFIG_DIR, 'jury')

COMMON_CLIENT_CONFIG = os.path.join(RESOURCES, 'team_client_common.txt')
COMMON_VULNBOX_CONFIG = os.path.join(RESOURCES, 'vulnbox_common.txt')
COMMON_JURY_CONFIG = os.path.join(RESOURCES, 'jury_client_common.txt')

COMMON_VULNBOX_SERVER_CONFIG = os.path.join(RESOURCES, 'vulnbox_server_common.txt')
COMMON_TEAM_SERVER_CONFIG = os.path.join(RESOURCES, 'team_server_common.txt')
COMMON_JURY_SERVER_CONFIG = os.path.join(RESOURCES, 'jury_server_common.txt')

CA_CERT_NAME = 'ca.crt'
CA_KEY_NAME = 'ca.key'
DHPARAM_NAME = 'dh2048.pem'

CA_CERT_PATH = os.path.join(SERVER_CONFIG_DIR, CA_CERT_NAME)
CA_KEY_PATH = os.path.join(SERVER_CONFIG_DIR, CA_KEY_NAME)
DHPARAM_PATH = os.path.join(SERVER_CONFIG_DIR, DHPARAM_NAME)

VULNBOX_IFACE_TEMPLATE = 'vuln{num}'
VULNBOX_PORT_TEMPLATE = '31{num}'

TEAM_IFACE_TEMPLATE = 'team{num}'
TEAM_PORT_TEMPLATE = '30{num}'

JURY_IFACE_TEMPLATE = 'jury'
JURY_PORT_TEMPLATE = '32000'

TEAM_SERVER_NAME_TEMPLATE = 'team_server_{num}'
VULNBOX_SERVER_NAME_TEMPLATE = 'vulnbox_server_{num}'

TEAM_SERVER_DUMP_PATH_TEMPLATE = os.path.join(
    CLIENT_SERVER_CONFIG_DIR,
    f'{TEAM_SERVER_NAME_TEMPLATE}.conf',
)

VULNBOX_SERVER_DUMP_PATH_TEMPLATE = os.path.join(
    VULNBOX_SERVER_CONFIG_DIR,
    f'{VULNBOX_SERVER_NAME_TEMPLATE}.conf',
)

JURY_SERVER_DUMP_PATH_TEMPLATE = os.path.join(
    JURY_SERVER_CONFIG_DIR,
    'jury.conf',
)

TEAM_SUBNET = 60
VULNBOX_SUBNET = 70
JURY_SUBNET = 10

TEAM_CONFIG_DIR = os.path.join(CLIENT_CONFIG_DIR, 'team{team_num}')
