from utils import ipv4


def test_networks_to_dfa():
    networks = ['1.1.1.0/24', '1.2.3.32/27', '2.2.2.2/32', '3.0.0.0/8']
    dfa = ipv4.networks_to_dfa(networks)
    # 1.1.1.42 is in 1.1.1.0/24
    assert dfa.accepts_input(ipv4.ip_to_bin('1.1.1.42'))
    # 1.2.3.33 is in 1.2.3.32/27
    assert dfa.accepts_input(ipv4.ip_to_bin('1.2.3.33'))
    # 2.2.2.2 is in 2.2.2.2/32
    assert dfa.accepts_input(ipv4.ip_to_bin('2.2.2.2'))
    # 3.3.3.3 is in 3.0.0.0/8
    assert dfa.accepts_input(ipv4.ip_to_bin('3.3.3.3'))
    # 42.42.42.42 is not in any of the listed networks
    assert not dfa.accepts_input(ipv4.ip_to_bin('42.42.42.42'))
    # 1.2.3.64 is just outside of 1.2.3.32/27
    assert not dfa.accepts_input(ipv4.ip_to_bin('1.2.3.64'))


def test_normalize_cidr():
    expected_cidrs = ['1.1.1.1/32', '1.1.1.1/24']
    cidrs = list(ipv4.normalize_cidr(['1.1.1.1', '1.1.1.1/24']))
    assert cidrs == expected_cidrs


def test_ip_to_bin():
    assert '00000001000000010000000100000011' == ipv4.ip_to_bin('1.1.1.3')


def test_ip_to_hex():
    assert '01010103' == ipv4.ip_to_hex('1.1.1.3')


def test_networks_to_prefixes():
    expected_prefixes = [
        '00000001',
        '0000000100000001',
        '00000001000000100000001100000100',
    ]
    prefixes = list(
        ipv4._networks_to_prefixes(['1.0.0.0/8', '1.1.0.0/16', '1.2.3.4/32'])
    )
    assert prefixes == expected_prefixes
