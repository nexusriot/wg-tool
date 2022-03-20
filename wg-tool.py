import os
import subprocess
import ipaddress
from config import *


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
    output = subprocess.check_output(("wg", "pubkey"), stdin=ps.stdout)
    ps.wait()
    with open(PUBLIC_KEY, "w") as fh:
        fh.write(output)


def init_server_config(do_forward=True):
    config_file = os.path.join(SERVER_CONFIG_BASE_PATH, WG_DEV) + ".conf"
    private_key = get_private_key()
    net = ipaddress.IPv4Network(NETWORK)
    first_addr = net[1]  # get the first addr for server config
    with open(config_file, "w") as fh:
        fh.write("[Interface]\n")
        fh.write("PrivateKey = {private_key}\n".format(private_key=private_key))
        fh.write("ListenPort = {listen_port}\n".format(listen_port=LISTEN_PORT))
        fh.write("Address = {first_addr}/{pref_len}\n".format(first_addr=first_addr, pref_len=net.prefixlen))
        fh.write("SaveConfig = true\n")
        if do_forward:
            fh.write(forward_rules(ENA_DEV, WG_DEV))


if __name__ == "__main__":
    init_server_config()
