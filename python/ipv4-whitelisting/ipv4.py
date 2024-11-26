from typing import Iterable, Iterator

from automata.fa.dfa import DFA


def networks_to_dfa(networks: Iterable[str]) -> DFA:
    """From the list of given ipv4 networks creates a deterministic finite
    automata (DFA) that will accept IP addresses that belong to any of the
    given networks.
    """
    prefixes = _networks_to_prefixes(networks)
    networks_dfa = DFA.empty_language({'0', '1'})
    for prefix in prefixes:
        prefix_dfa = DFA.from_prefix({'0', '1'}, prefix)
        # Create union of DFAs
        networks_dfa |= prefix_dfa
    return networks_dfa


def normalize_cidr(ips: Iterable[str]) -> Iterator[str]:
    """Normalize list of ips to always include network mask (e.g., /24, /32).
    1.1.1.1 -> 1.1.1.1/32
    1.1.1.0/24 -> 1.1.1.0/24
    """
    for ip in ips:
        if len(ip.split("/")) == 1:
            ip += "/32"
        yield ip


def ip_to_bin(ip: str) -> str:
    """Translate IPv4 to binary string representation.
    1.1.1.3 -> 00000001000000010000000100000011
    """
    parts = ip.split(".")
    bin_ip = "".join([f"{int(i):08b}" for i in parts])
    return bin_ip


def ip_to_hex(ip: str) -> str:
    """Translate IPv4 to hexadecimal string representation.
    1.1.1.3 -> 01010103
    """
    parts = ip.split(".")
    hex_ip = "".join([f"{int(i):02x}" for i in parts])
    return hex_ip


def _networks_to_prefixes(networks: Iterable[str]) -> Iterator[str]:
    """Create a language of binary prefixies corresponding to the given set of
    networks. The language can then be used to construct a deterministic finite
    automata.
    [1.0.0.0/8, 1.1.0.0/16, 1.2.3.4/32] -> [00000001, 0000000100000001,
    00000001000000100000001100000100]
    """
    for network in networks:
        ip, mask = network.split("/")
        ip_bin = ip_to_bin(ip)
        net_bin_prefix = ip_bin[: int(mask)]
        yield net_bin_prefix
