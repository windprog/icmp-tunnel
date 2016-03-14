#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Author  :   windpro
E-mail  :   windprog@gmail.com
Date    :   16/3/14
Desc    :   
"""
import re
import requests
from netaddr import IPNetwork, IPAddress


IPN_FILE = 'ipn.txt'


def ipn_deduplication(ipn_str_list):
    all_ip_network = {IPNetwork(item) for item in ipn_str_list}
    for value in list(all_ip_network):
        all_ip_network.remove(value)
        is_sub_network = False
        for check_value in all_ip_network:
            if value in check_value:
                is_sub_network = True
                break
        if not is_sub_network:
            all_ip_network.add(value)
    return all_ip_network


def get_as_num_ip(as_num):
    all_ip_network = set()
    as_num = str(as_num)
    assert as_num.isdigit()
    html = requests.get('https://ipinfo.io/AS%s' % as_num).content
    pattern = '<a href="/AS(\d+)/(.*?)">'
    for num, ip_network in re.findall(pattern, html):
        if num == as_num:
            all_ip_network.add(ip_network)

    return list(ipn_deduplication(all_ip_network))


if __name__ == '__main__':
    all_as_num = [
        # GOOGLE Autonomous System Number
        # http://mxtoolbox.com/SuperTool.aspx?action=asn:google&run=toolpage#
        '16591',  # Google Fiber Inc.
        '15169',  # Google Inc.
        '22577',  # Google Inc.
        '36039',  # Google Inc.
        '36040',  # Google Inc.
        '36384',  # Google Incorporated
        '41264',  # Google Switzerland GmbH
        '36492',  # Google, Inc.
    ]
    all_ipn = []
    for asn in all_as_num:
        all_ipn.extend(get_as_num_ip(asn))

    # append aws ips
    aws_ipn_list = []
    for ip_info in requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json').json()['prefixes']:
        aws_ipn_list.append(ip_info['ip_prefix'])
    all_ipn.extend(ipn_deduplication(aws_ipn_list))

    # 排序
    all_ipn.sort()
    with file(IPN_FILE, 'w+') as f:
        for ipn in all_ipn:
            f.write(str(ipn) + '\n')

