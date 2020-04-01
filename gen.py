#!/usr/bin/env python3

import argparse
import os
import re
import shutil

from jinja2 import Environment, FileSystemLoader, select_autoescape

if __name__ == '__main__':
    import config
    import crypto_utils
else:
    from . import config
    from . import crypto_utils

jenv = Environment(
    loader=FileSystemLoader(config.TEMPLATES_PATH),
    autoescape=select_autoescape(['html', 'xml'])
)


def initialize():
    if os.path.exists(config.RESULT_DIR):
        shutil.rmtree(config.RESULT_DIR)

    os.makedirs(config.TEAM_SERVER_DIR, exist_ok=True)
    os.makedirs(config.VULN_SERVER_DIR, exist_ok=True)
    os.makedirs(config.JURY_SERVER_DIR, exist_ok=True)

    os.makedirs(config.TEAM_CLIENT_DIR, exist_ok=True)
    os.makedirs(config.VULN_CLIENT_DIR, exist_ok=True)
    os.makedirs(config.JURY_CLIENT_DIR, exist_ok=True)


def generate(team_list, per_team, vpn_server, gen_team, gen_jury, gen_vuln):
    dhparam = crypto_utils.get_dhparam()

    ca_cert, ca_key = crypto_utils.create_ca(CN='cbsctf.live')
    ca_cert_dump = crypto_utils.dump_file_in_mem(ca_cert).decode()

    if gen_team or gen_vuln:
        for team_num in team_list:
            formatted_team = str(team_num).zfill(3)
            if gen_team:
                team_static_key = crypto_utils.generate_static_key()

                team_client_dir = os.path.join(config.TEAM_CLIENT_DIR, f'team{formatted_team}')
                os.makedirs(team_client_dir, exist_ok=True)

                for person in range(1, per_team + 1):
                    client_name = f'team{formatted_team}_{person}'

                    cert, key = crypto_utils.generate_subnet_certs(
                        ca_cert=ca_cert,
                        ca_key=ca_key,
                        client_name=client_name,
                        serial=0x0C,
                        is_server=False,
                    )

                    template = jenv.get_template('team_client.j2')
                    rendered = template.render(
                        config=config,
                        server_host=vpn_server,
                        team_num=team_num,
                        ca_cert=ca_cert_dump,
                        cert=cert,
                        key=key,
                        static_key=team_static_key,
                    )

                    ovpn_dump_path = os.path.join(team_client_dir, f'{client_name}.ovpn')
                    with open(ovpn_dump_path, 'w') as f:
                        f.write(rendered)

                server_name = f'team_server{formatted_team}'
                cert, key = crypto_utils.generate_subnet_certs(
                    ca_cert=ca_cert,
                    ca_key=ca_key,
                    client_name=server_name,
                    serial=0x0C,
                    is_server=True,
                )

                template = jenv.get_template('team_server.j2')
                rendered = template.render(
                    config=config,
                    server_host=vpn_server,
                    team_num=team_num,
                    ca_cert=ca_cert_dump,
                    cert=cert,
                    key=key,
                    static_key=team_static_key,
                    dhparam=dhparam,
                )

                conf_dump_path = os.path.join(config.TEAM_SERVER_DIR, f'{server_name}.conf')
                with open(conf_dump_path, 'w') as f:
                    f.write(rendered)

            if gen_vuln:
                vulnbox_static_key = crypto_utils.generate_static_key()

                template = jenv.get_template('vuln_client.j2')
                rendered = template.render(
                    config=config,
                    server_host=vpn_server,
                    team_num=team_num,
                    static_key=vulnbox_static_key,
                )

                ovpn_dump_path = os.path.join(config.VULN_CLIENT_DIR, f'vuln{team_num}.ovpn')
                with open(ovpn_dump_path, 'w') as f:
                    f.write(rendered)

                template = jenv.get_template('vuln_server.j2')
                rendered = template.render(
                    config=config,
                    server_host=vpn_server,
                    team_num=team_num,
                    static_key=vulnbox_static_key,
                )

                ovpn_dump_path = os.path.join(config.VULN_SERVER_DIR, f'vuln_server{formatted_team}.conf')
                with open(ovpn_dump_path, 'w') as f:
                    f.write(rendered)

    if gen_jury:
        jury_static_key = crypto_utils.generate_static_key()

        template = jenv.get_template('jury_client.j2')
        rendered = template.render(
            config=config,
            server_host=vpn_server,
            static_key=jury_static_key,
        )

        ovpn_dump_path = os.path.join(config.JURY_CLIENT_DIR, f'config.ovpn')
        with open(ovpn_dump_path, 'w') as f:
            f.write(rendered)

        template = jenv.get_template('jury_server.j2')
        rendered = template.render(
            config=config,
            server_host=vpn_server,
            static_key=jury_static_key,
        )

        ovpn_dump_path = os.path.join(config.JURY_SERVER_DIR, f'jury.conf')
        with open(ovpn_dump_path, 'w') as f:
            f.write(rendered)


def run(team_list, per_team, vpn_server, gen_team=True, gen_jury=True, gen_vuln=True):
    initialize()
    generate(
        team_list=team_list,
        per_team=per_team,
        vpn_server=vpn_server,
        gen_team=gen_team,
        gen_jury=gen_jury,
        gen_vuln=gen_vuln,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate openvpn configuration for AD CTFs')
    parser.add_argument('--server', '-s', type=str, help='Openvpn server host', required=True)
    parser.add_argument('--per-team', type=int, default=2, metavar='N', help='Number of configs per team')
    parser.add_argument('--team', help='Generate config for teams', action='store_true')
    parser.add_argument('--jury', help='Generate config for jury', action='store_true')
    parser.add_argument('--vuln', help='Generate config for vulnboxes', action='store_true')

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--teams', '-t', type=int, metavar='N', help='Team count')
    group.add_argument('--range', type=str, metavar='N-N', help='Range of teams (inclusive)')
    group.add_argument('--list', type=str, metavar='N,N,...', help='List of teams')

    args = parser.parse_args()

    teams = None
    if args.team or args.vuln:
        if args.teams:
            teams = range(1, args.teams + 1)
        elif args.range:
            match = re.search(r"(\d+)-(\d+)", args.range)
            if not match:
                print('Invalid range')
                exit(1)

            teams = range(int(match.group(1)), int(match.group(2)) + 1)
        else:
            teams = list(map(int, args.list.split(',')))

    run(team_list=teams, per_team=args.per_team, vpn_server=args.server, gen_team=args.team, gen_jury=args.jury,
        gen_vuln=args.vuln)

    print(f"Done generating config for {len(teams or [])} teams")
