#!/usr/bin/env python3

import os
import shutil
import crypto_utils
import argparse

from auxiliary import format_number


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESOURCES = os.path.join(BASE_DIR, 'resources')
RESULT_DIR = os.path.join(BASE_DIR, 'result')

SERVER_CONFIG_DIR = os.path.join(RESULT_DIR, 'server')
CLIENT_CONFIG_DIR = os.path.join(RESULT_DIR, 'client')
VULNBOX_CONFIG_DIR = os.path.join(RESULT_DIR, 'vulnbox')

SERVER_CRYPTO_DIR = os.path.join(SERVER_CONFIG_DIR, 'crypto')

COMMON_CLIENT_CONFIG = os.path.join(RESOURCES, 'client_common.txt')
COMMON_SERVER_CONFIG = os.path.join(RESOURCES, 'server_common.txt')
COMMON_VULNBOX_CONFIG = os.path.join(RESOURCES, 'vulnbox_common.txt')

CA_CERT_NAME = 'ca.crt'
CA_KEY_NAME = 'ca.key'
DHPARAM_NAME = 'dh2048.pem'

CA_CERT_PATH = os.path.join(SERVER_CONFIG_DIR, CA_CERT_NAME)
CA_KEY_PATH = os.path.join(SERVER_CONFIG_DIR, CA_KEY_NAME)
DHPARAM_PATH = os.path.join(SERVER_CONFIG_DIR, DHPARAM_NAME)

VULNBOX_IFACE_PREFIX = 'vuln'
VULNBOX_PORT_PREFIX = '310'

TEAM_IFACE_PREFIX = 'team'
TEAM_PORT_PREFIX = '300'

TEAM_CONFIG_DIR = os.path.join(CLIENT_CONFIG_DIR, 'team{team_num}')


def gen_server_config(server_num, server_type, net, mask, iface_prefix, port_prefix):
    key_filename = f'{server_type}_server_{server_num}.key'
    cert_filename = f'{server_type}_server_{server_num}.crt'

    key_path = os.path.join(SERVER_CRYPTO_DIR, key_filename)
    cert_path = os.path.join(SERVER_CRYPTO_DIR, cert_filename)

    dump_path = os.path.join(SERVER_CONFIG_DIR, f'{server_type}_server_{server_num}.conf')
    crypto_utils.generate_server_conf(
        ca_cert_filename=CA_CERT_NAME,
        ca_cert_path=CA_CERT_PATH,
        ca_key_path=CA_KEY_PATH,
        dh_param_filename=DHPARAM_NAME,
        server_cert_filename=cert_filename,
        server_cert_path=cert_path,
        server_key_filename=key_filename,
        server_key_path=key_path,
        common_config_filename=COMMON_SERVER_CONFIG,
        server_num=server_num,
        net=net,
        mask=mask,
        serial=0x0C,
        iface_prefix=iface_prefix,
        port_prefix=port_prefix,
        out_path=dump_path,
    )


def initialize(team_count):
    if os.path.exists(RESULT_DIR):
        shutil.rmtree(RESULT_DIR)

    os.makedirs(SERVER_CONFIG_DIR)
    os.makedirs(CLIENT_CONFIG_DIR)
    os.makedirs(VULNBOX_CONFIG_DIR)
    os.makedirs(SERVER_CRYPTO_DIR)

    for team_num in range(1, team_count + 1):
        os.makedirs(TEAM_CONFIG_DIR.format(team_num=team_num))


def main(team_count, per_team, vpn_server):
    dump_file = open(DHPARAM_PATH, 'w')
    dhparams_gen_proc = crypto_utils.start_dhparams_gen(dump_file)

    ca_cert, ca_key = crypto_utils.create_ca(CN='ctforces.com')
    ca_cert_dump = crypto_utils.dump_file_in_mem(ca_cert).decode()
    ca_key_dump = crypto_utils.dump_file_in_mem(ca_key).decode()

    with open(CA_CERT_PATH, 'w') as f:
        f.write(ca_cert_dump)

    with open(CA_KEY_PATH, 'w') as f:
        f.write(ca_key_dump)

    for team_num in range(1, team_count + 1):
        formatted_num = format_number(team_num)

        for person in range(1, per_team + 1):
            ovpn_dump_path = os.path.join(
                CLIENT_CONFIG_DIR,
                TEAM_CONFIG_DIR.format(team_num=team_num),
                f'team{formatted_num}_{person}.ovpn',
            )

            crypto_utils.generate_client_ovpn(
                ca_cert_path=CA_CERT_PATH,
                ca_key_path=CA_KEY_PATH,
                client_num=formatted_num,
                server_host=vpn_server,
                serial=0x0C,
                common_config_filename=COMMON_CLIENT_CONFIG,
                client_type=TEAM_IFACE_PREFIX,
                port_prefix=TEAM_PORT_PREFIX,
                out_path=ovpn_dump_path,
            )

        ovpn_dump_path = os.path.join(VULNBOX_CONFIG_DIR, f'vuln_{formatted_num}.ovpn')
        crypto_utils.generate_client_ovpn(
            ca_cert_path=CA_CERT_PATH,
            ca_key_path=CA_KEY_PATH,
            client_num=formatted_num,
            server_host=vpn_server,
            serial=0x0C,
            common_config_filename=COMMON_VULNBOX_CONFIG,
            client_type=VULNBOX_IFACE_PREFIX,
            port_prefix=VULNBOX_PORT_PREFIX,
            out_path=ovpn_dump_path,
        )

        gen_server_config(
            server_num=formatted_num,
            server_type='team',
            net=60,
            mask='255.255.255.0',
            iface_prefix=TEAM_IFACE_PREFIX,
            port_prefix=TEAM_PORT_PREFIX,
        )

        gen_server_config(
            server_num=formatted_num,
            server_type='vulnbox',
            net=70,
            mask='255.255.255.254',
            iface_prefix=VULNBOX_IFACE_PREFIX,
            port_prefix=VULNBOX_PORT_PREFIX,
        )

    dhparams_gen_proc.wait()
    dump_file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate openvpn configuration for AD CTFs')
    parser.add_argument('--teams', '-t', type=int, metavar='N', help='Team count', required=True)
    parser.add_argument('--server', '-s', type=str, help='Openvpn server host', required=True)
    parser.add_argument('--per-team', type=int, default=2, metavar='N', help='Number of configs per team')
    args = parser.parse_args()
    initialize(team_count=args.teams)
    main(team_count=args.teams, per_team=args.per_team, vpn_server=args.server)
    print(f"Done generating config for {args.teams} teams")
