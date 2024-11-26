from flexmock import flexmock

from utils import whitelist
from utils.ipv4 import ip_to_bin, networks_to_dfa


def test_get_whitelist_dfa():
    # _load_whitelist_group should be called twice, once for 'benign' and once
    # for 'transient' whitelist group.
    flexmock(whitelist).should_receive('_load_whitelist_group').with_args(
        'benign'
    ).and_return([['1.1.1.1', '192.168.0.0/16']]).once()
    flexmock(whitelist).should_receive('_load_whitelist_group').with_args(
        'transient'
    ).and_return([['1.2.3.4', '1.2.3.33/27']]).once()
    # normalize_cidr should be called 3 times, once for bening list
    # once for transient list and once for custom_ips list
    flexmock(whitelist).should_call('normalize_cidr').times(3)

    whitelist_dfa = whitelist.get_whitelist_dfa(['8.8.8.8', '3.0.0.0/8'])

    assert whitelist_dfa.accepts_input(ip_to_bin('8.8.8.8'))
    assert whitelist_dfa.accepts_input(ip_to_bin('3.3.3.3'))
    assert whitelist_dfa.accepts_input(ip_to_bin('1.2.3.4'))
    assert whitelist_dfa.accepts_input(ip_to_bin('1.2.3.34'))
    assert whitelist_dfa.accepts_input(ip_to_bin('1.1.1.1'))
    assert whitelist_dfa.accepts_input(ip_to_bin('192.168.0.1'))
    assert not whitelist_dfa.accepts_input(ip_to_bin('42.42.42.42'))


def test_filter_out_whitelisted():
    flexmock(whitelist).should_call('ip_to_bin').times(4)
    whitelist_dfa = networks_to_dfa(['1.1.1.1/32', '192.168.0.0/16'])
    ip_to_filter = ['1.1.1.1', '2.2.2.2', '192.168.0.1', '192.167.0.1']
    expected_filtered = ['2.2.2.2', '192.167.0.1']
    filtered = list(whitelist.filter_out_whitelisted(ip_to_filter, whitelist_dfa))
    assert sorted(filtered) == sorted(expected_filtered)


def test_load_whitelist_group():
    flexmock(whitelist).should_receive('list_objects').with_args(
        'whitelists', 'benign/'
    ).and_return(['benign/private.json', 'benign/cloudflare.json']).once()
    flexmock(whitelist).should_receive('read_json').with_args(
        'whitelists', 'benign/private.json'
    ).and_return(['192.164.0.0/16', '10.0.0.0/8']).once()
    flexmock(whitelist).should_receive('read_json').with_args(
        'whitelists', 'benign/cloudflare.json'
    ).and_return(None).once()

    group_whitelist = list(whitelist._load_whitelist_group('benign'))
    assert group_whitelist == [['192.164.0.0/16', '10.0.0.0/8']]
