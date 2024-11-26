import logging
from typing import Iterator, List, Set

from automata.fa.dfa import DFA

from utils.ipv4 import ip_to_bin, networks_to_dfa, normalize_cidr
from utils.s3 import list_objects, read_json

_WHITELIST_GROUPS = (
    'benign',
    'transient',
)


def get_whitelist_dfa(custom_ips: List[str] = []) -> DFA:
    """Create a DFA from all whitelist groups stored in MinIO.
    A whitelist group is represented as a "directory" in MinIO's whitelists
    bucket. Each directory then can contain multiple JSON files (e.g.,
    bening/private.json, bening/cloudflare.json) where each the files containe
    a list of IP addresses. For example, content of bening/private.json is:

    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ]

    'transient' whitelist group is a special group, where JSON files expire
    automatically after 15 days - the purpose of this is to be able to
    temporarillay whitelist a set of IP addresses.

    On top of the whitelists stored in MinIO a custom set of IP
    addresses/networks can be provided via custom_ips parameter.
    """
    networks: Set[str] = set()
    networks.update(normalize_cidr(custom_ips))
    for group in _WHITELIST_GROUPS:
        for whitelist_content in _load_whitelist_group(group):
            networks.update(normalize_cidr(whitelist_content))
    networks_dfa = networks_to_dfa(networks)
    return networks_dfa


def filter_out_whitelisted(ips: List[str], whitelist_dfa: DFA) -> Iterator[str]:
    """Take a list of IPv4 addresses and filter out those that are accepted by
    the given whitelist DFA.
    """
    for ip in ips:
        ip_bin = ip_to_bin(ip)
        if not whitelist_dfa.accepts_input(ip_bin):
            yield ip


def _load_whitelist_group(whitelist_group: str) -> Iterator[List[str]]:
    """One-by-one read and yield content of files in the given whitelist group
    from MinIO storage.
    """
    assert whitelist_group in _WHITELIST_GROUPS
    whitelist_group_s3_prefix = f"{whitelist_group}/"
    whitelists_in_group = list(list_objects('whitelists', whitelist_group_s3_prefix))
    if len(whitelists_in_group) == 0:
        logging.warning(f"There are no whitelists in group {whitelist_group}")
    for whitelist_path in whitelists_in_group:
        whitelist_content = read_json("whitelists", str(whitelist_path))
        if whitelist_content is None:
            logging.warning(f"Whitelist {whitelist_path} is empty")
            continue
        yield whitelist_content
