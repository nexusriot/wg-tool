#!/usr/bin/env  python3

import argparse
import os
import subprocess
import ipaddress
from config import *


class ServerConfigException(Exception):
    pass


class ClientConfigException(Exception):
    pass


def forward_rules(ena_dev, wg_dev):
    return """
PostUp = iptables -A FORWARD -i {wgdev} -j ACCEPT; iptables -t nat -A POSTROUTING -o {enadev} -j MASQUERADE; ip6tables -A FORWARD -i {wgdev} -j ACCEPT; ip6tables -t nat -A POSTROUTING -o {enadev} -j MASQUERADE
PostDown = iptables -D FORWARD -i {wgdev} -j ACCEPT; iptables -t nat -D POSTROUTING -o {enadev} -j MASQUERADE; ip6tables -D FORWARD -i {wgdev} -j ACCEPT; ip6tables -t nat -D POSTROUTING -o {enadev} -j MASQUERADE\n""".format(enadev=ena_dev, wgdev=wg_dev)


def create_private_key():
    with open(PRIVATE_KEY, 'w') as fh:
        fh.write(subprocess.check_output(["wg", "genkey"]).decode().strip())
    subprocess.check_call(["chmod", "go=", "/etc/wireguard/private.key"])


def get_private_key():
    with open(PRIVATE_KEY, "r") as fh:
        return fh.read()


def create_public_key():
    private_key = get_private_key()
    ps = subprocess.Popen(('echo', private_key), stdout=subprocess.PIPE)
    output = subprocess.check_output(("wg", "pubkey"), stdin=ps.stdout).decode().strip()
    ps.wait()
    with open(PUBLIC_KEY, "w") as fh:
        fh.write(output)


def init_server_config(addr=None, do_forward=True):
    if not ENDPOINT:
        raise ServerConfigException("Empty endpoint ip")
    create_private_key()
    create_public_key()
    config_file = os.path.join(SERVER_CONFIG_BASE_PATH, WG_DEV) + ".conf"
    private_key = get_private_key()
    pref_len = 24  # by default 24
    if not addr:
        net = ipaddress.IPv4Network(NETWORK)
        addr = net[1]  # get the first addr for server config
        pref_len = net.prefixlen
    with open(config_file, "w") as fh:
        fh.write("[Interface]\n")
        fh.write("PrivateKey = {private_key}\n".format(private_key=private_key))
        fh.write("ListenPort = {listen_port}\n".format(listen_port=LISTEN_PORT))
        fh.write("Address = {first_addr}/{pref_len}\n".format(first_addr=addr, pref_len=pref_len))
        fh.write("SaveConfig = true\n")
        if do_forward:
            fh.write(forward_rules(ENA_DEV, WG_DEV))


def init_client_config():
    pass


def main():
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(dest='command')
    config_server = subparser.add_parser('server')
    config_client = subparser.add_parser('client')
    config_server.add_argument('--addr', type=str, required=False, default=None)
    config_client.add_argument('--client_addr', type=str, required=False, default=None)

    args = parser.parse_args()
    if args.command == 'server':
        init_server_config(args.addr)


if __name__ == "__main__":
    main()
