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


def get_public_key():
    with open(PUBLIC_KEY, "r") as fh:
        return fh.read()


def create_public_key():
    private_key = get_private_key()
    ps = subprocess.Popen(('echo', private_key), stdout=subprocess.PIPE)
    public_key = subprocess.check_output(("wg", "pubkey"), stdin=ps.stdout).decode().strip()
    ps.wait()
    with open(PUBLIC_KEY, "w") as fh:
        fh.write(public_key)


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
    subprocess.check_call(["systemctl", "enable", "wg-quick@wg0.service"])
    subprocess.check_call(["systemctl", "start", "wg-quick@wg0.service"])


def add_peer(client_public_key, client_addr):
    subprocess.check_output(["wg", "set",  WG_DEV, "peer", client_public_key, "allowed-ips", client_addr])


def init_client_config(name, client_addr):
    if not os.path.isfile(PUBLIC_KEY) or not os.path.isfile(PRIVATE_KEY):
        raise ClientConfigException("please configure server keys first")
    server_public_key = get_public_key()
    client_private_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
    ps = subprocess.Popen(('echo', client_private_key), stdout=subprocess.PIPE)
    client_public_key = subprocess.check_output(("wg", "pubkey"), stdin=ps.stdout).decode().strip()
    ps.wait()
    config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), name + ".conf")
    address = "%s/24" % client_addr
    with open(config_file, "w") as fh:
        fh.write("[Interface]\n")
        fh.write("PrivateKey = {private_key}\n".format(private_key=client_private_key))
        fh.write("Address = {address}\n\n".format(address=address))
        fh.write("[Peer]\n")
        fh.write("PublicKey = {server_public_key}\n".format(server_public_key=server_public_key))
        fh.write("AllowedIPs = 0.0.0.0/0\n")
        fh.write("Endpoint = {endpoint_ip}:{endpoint_port}\n".format(endpoint_ip=ENDPOINT, endpoint_port=LISTEN_PORT))
    add_peer(client_public_key, client_addr)


def main():
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(dest='command')
    config_server = subparser.add_parser('server')
    config_client = subparser.add_parser('client')
    config_server.add_argument('--addr', type=str, required=False, default=None)  # if not set will take first net addr
    config_client.add_argument('--client_addr', type=str, required=True)
    config_client.add_argument('--name', type=str, required=True)

    args = parser.parse_args()
    if args.command == 'server':
        init_server_config(args.addr)
    elif args.command == 'client':
        init_client_config(args.name, args.client_addr)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
