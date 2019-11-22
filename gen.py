#!/usr/bin/env python3

import argparse
import os
import shutil
import re

from . import config
from . import crypto_utils
from .auxiliary import format_number


def gen_subnet_server_config(
        server_num,
        server_type,
        net,
        mask,
        common_config_path,
        name_template,
        port_template,
        iface_template,
        dump_path_template,
        static_key):
    key_filename = f'{server_type}_server_{server_num}.key'
    cert_filename = f'{server_type}_server_{server_num}.crt'

    crypto_utils.generate_subnet_server_conf(
        static_key=static_key,
        ca_cert_filename=config.CA_CERT_NAME,
        ca_cert_path=config.CA_CERT_PATH,
        ca_key_path=config.CA_KEY_PATH,
        dh_param_filename=config.DHPARAM_NAME,
        server_cert_filename=cert_filename,
        server_key_filename=key_filename,
        common_config_path=common_config_path,
        server_num=server_num,
        name_template=name_template,
        port_template=port_template,
        iface_template=iface_template,
        net=net,
        mask=mask,
        serial=0x0C,
        out_path_template=dump_path_template,
    )


def initialize(team_range):
    if os.path.exists(config.RESULT_DIR):
        shutil.rmtree(config.RESULT_DIR)

    os.makedirs(config.SERVER_CONFIG_DIR)
    os.makedirs(config.CLIENT_CONFIG_DIR)
    os.makedirs(config.VULNBOX_CONFIG_DIR)
    os.makedirs(config.JURY_CONFIG_DIR)

    for team_num in team_range:
        os.makedirs(config.TEAM_CONFIG_DIR.format(team_num=team_num))


def generate(team_range, per_team, vpn_server):
    dump_file = open(config.DHPARAM_PATH, 'w')

    # server DH parameters, needs to be awaited
    dhparams_gen_proc = crypto_utils.start_dhparams_gen(dump_file)

    # server crypto parameters
    ca_cert, ca_key = crypto_utils.create_ca(CN='ctforces.com')
    ca_cert_dump = crypto_utils.dump_file_in_mem(ca_cert).decode()
    ca_key_dump = crypto_utils.dump_file_in_mem(ca_key).decode()

    with open(config.CA_CERT_PATH, 'w') as f:
        f.write(ca_cert_dump)

    with open(config.CA_KEY_PATH, 'w') as f:
        f.write(ca_key_dump)

    for team_num in team_range:
        team_static_key = crypto_utils.generate_static_key()
        formatted_num = format_number(team_num)

        for person in range(1, per_team + 1):
            client_name = f'team{formatted_num}_{person}'
            ovpn_dump_path = os.path.join(
                config.CLIENT_CONFIG_DIR,
                config.TEAM_CONFIG_DIR.format(team_num=team_num),
                f'{client_name}.ovpn',
            )

            # team player's ovpn file
            crypto_utils.generate_subnet_client_ovpn(
                ca_cert_path=config.CA_CERT_PATH,
                ca_key_path=config.CA_KEY_PATH,
                client_num=formatted_num,
                client_name=client_name,
                server_host=vpn_server,
                serial=0x0C,
                common_config_filename=config.COMMON_CLIENT_CONFIG,
                server_port_template=config.TEAM_PORT_TEMPLATE,
                out_path=ovpn_dump_path,
                static_key=team_static_key,
            )

        # team main vpn server config
        gen_subnet_server_config(
            server_num=formatted_num,
            server_type='team',
            net=60,
            mask='255.255.255.0',
            iface_template=config.TEAM_IFACE_TEMPLATE,
            port_template=config.TEAM_PORT_TEMPLATE,
            static_key=team_static_key,
            common_config_path=config.COMMON_TEAM_SERVER_CONFIG,
            dump_path_template=config.TEAM_SERVER_DUMP_PATH_TEMPLATE,
            name_template=config.TEAM_SERVER_NAME_TEMPLATE,
        )

        ovpn_dump_path = os.path.join(config.VULNBOX_CONFIG_DIR, f'vuln{team_num}.ovpn')
        vulnbox_static_key = crypto_utils.generate_static_key()

        # team vulnbox ovpn
        crypto_utils.generate_p2p_client_ovpn(
            static_key=vulnbox_static_key,
            client_num=formatted_num,
            server_host=vpn_server,
            common_config_filename=config.COMMON_VULNBOX_CONFIG,
            server_port_template=config.VULNBOX_PORT_TEMPLATE,
            net=config.VULNBOX_SUBNET,
            out_path=ovpn_dump_path,
        )

        # team vulnbox p2p server
        crypto_utils.generate_p2p_server_conf(
            static_key=vulnbox_static_key,
            common_config_path=config.COMMON_VULNBOX_SERVER_CONFIG,
            iface_template=config.VULNBOX_IFACE_TEMPLATE,
            port_template=config.VULNBOX_PORT_TEMPLATE,
            net=config.VULNBOX_SUBNET,
            server_num=formatted_num,
            out_path_template=config.VULNBOX_SERVER_DUMP_PATH_TEMPLATE,
        )

    jury_static_key = crypto_utils.generate_static_key()
    ovpn_dump_path = os.path.join(config.JURY_CONFIG_DIR, f'config.ovpn')

    # jury client ovpn
    crypto_utils.generate_p2p_client_ovpn(
        static_key=jury_static_key,
        client_num='10',
        server_host=vpn_server,
        common_config_filename=config.COMMON_JURY_CONFIG,
        server_port_template=config.JURY_PORT_TEMPLATE,
        net=config.JURY_SUBNET,
        out_path=ovpn_dump_path,
    )

    # jury server config
    crypto_utils.generate_p2p_server_conf(
        static_key=jury_static_key,
        common_config_path=config.COMMON_JURY_SERVER_CONFIG,
        iface_template=config.JURY_IFACE_TEMPLATE,
        port_template=config.JURY_PORT_TEMPLATE,
        net=config.JURY_SUBNET,
        server_num='10',
        out_path_template=config.JURY_SERVER_DUMP_PATH_TEMPLATE,
    )

    print('Waiting for dhparam, that could take a minute...')
    dhparams_gen_proc.wait()
    dump_file.close()


def run(team_range, per_team, vpn_server):
    initialize(team_range=team_range)
    generate(team_range=team_range, per_team=per_team, vpn_server=vpn_server)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate openvpn configuration for AD CTFs')
    parser.add_argument('--server', '-s', type=str, help='Openvpn server host', required=True)
    parser.add_argument('--per-team', type=int, default=2, metavar='N', help='Number of configs per team')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--teams', '-t', type=int, metavar='N', help='Team count', required=True)
    group.add_argument('--range', '-t', type=str, metavar='N-N', help='Range of teams (inclusive)', required=True)

    args = parser.parse_args()

    if args.teams:
        t_range = range(1, args.teams + 1)
    else:
        borders = re.search(r"(\d+)-(\d+)", args.range)
        t_range = range(*borders)

    run(team_range=t_range, per_team=args.per_team, vpn_server=args.server)
    print(f"Done generating config for {args.teams} teams")
