#!/usr/bin/python3
# -*- coding: utf-8 -*-

import urllib.parse
import json
import urllib.request, urllib.error, urllib.parse
from argparse import ArgumentParser
import ipaddress
import json

def parse_args():
    parser = ArgumentParser()
    parser.add_argument('-f', '--file', dest='output', required=True,
                        help='输出的PAC文件名', metavar='PAC')
    parser.add_argument('-p', '--proxy', dest='proxy', required=True,
                        help='代理服务器, '
                             '例如, "PROXY 127.0.0.1:3128;"',
                        metavar='PROXY')
    parser.add_argument('--proxy-domains', dest='user_rule',
                        help='直接通过代理域名的文件，每行一个')
    parser.add_argument('--direct-domains', dest='direct_rule',
                        help='直连的域名文件，每行一个')
    parser.add_argument('--localtld-domains', dest='localtld_rule',
                        help='本地 TLD 规则文件, 不走代理, 每行一个，以 . 开头')
    parser.add_argument('--ip-file', dest='ip_file',
                        help='中国IP地址段文件')
    return parser.parse_args()

def convert_cidr(cidr):
    if '/' in cidr:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
        network_address = network.network_address
        prefixlen = network.prefixlen
    else:
        network = ipaddress.ip_address(cidr.strip())
        network_address = network
        prefixlen = network.max_prefixlen
    if network.version == 4:
        return hex(int(network_address))[2:] + '/' + str(prefixlen)
    else:
        return network.compressed

def generate_cnip_cidrs():
    """ 从文件中读取CIDR地址 """
    args = parse_args()
    with open(args.ip_file, 'r') as file:
        cidrs = file.read().splitlines()
        converted_cidrs = []
        for cidr in cidrs:
            converted_cidrs.append(convert_cidr(cidr))

    cidr_list = ','.join(converted_cidrs)
    return f"'{cidr_list}'.split(',')"

def generate_pac_fast(domains, proxy, direct_domains, cidrs, local_tlds):
    # render the pac file
    with open("./pac-template", "r", encoding="utf-8") as f:
        proxy_content = f.read()
    domains_list = []
    for domain in domains:
        domains_list.append(domain)
    proxy_content = proxy_content.replace('__PROXY__', json.dumps(str(proxy)))
    proxy_content = proxy_content.replace(
        '__DOMAINS__',
        json.dumps(domains_list, sort_keys=True, separators=(',', ':'))
    )

    direct_domains_list = []
    for domain in direct_domains:
        direct_domains_list.append(domain)
    proxy_content = proxy_content.replace(
        '__DIRECT_DOMAINS__',
        json.dumps(direct_domains_list, sort_keys=True, separators=(',', ':'))
    )

    proxy_content = proxy_content.replace(
        '__CIDRS__', cidrs
    )

    tlds_list = []
    for domain in local_tlds:
        tlds_list.append(domain)
    proxy_content = proxy_content.replace(
        '__LOCAL_TLDS__',
        json.dumps(tlds_list, sort_keys=True, separators=(',', ':'))
    )

    return proxy_content

def main():
    args = parse_args()
    user_rule = None
    direct_rule = None
    localtld_rule = None
    if args.user_rule:
        userrule_parts = urllib.parse.urlsplit(args.user_rule)
        if not userrule_parts.scheme or not userrule_parts.netloc:
            # It's not an URL, deal it as local file
            with open(args.user_rule, "r", encoding="utf-8") as f:
                user_rule = f.read()
        else:
            # Yeah, it's an URL, try to download it
            print('Downloading user rules file from %s' % args.user_rule)
            user_rule = urllib.request.urlopen(args.user_rule, timeout=10).read().decode('utf-8')
        user_rule = user_rule.splitlines(False)

    if args.direct_rule:
        directrule_parts = urllib.parse.urlsplit(args.direct_rule)
        if not directrule_parts.scheme or not directrule_parts.netloc:
            # It's not an URL, deal it as local file
            with open(args.direct_rule, "r", encoding="utf-8") as f:
                direct_rule = f.read()
        else:
            # Yeah, it's an URL, try to download it
            print("Downloading user rules file from %s" % args.user_rule)
            direct_rule = (
                urllib.request.urlopen(args.direct_rule, timeout=10)
                .read()
                .decode("utf-8")
            )
        direct_rule = direct_rule.splitlines(False)
    else:
        direct_rule = []

    if args.localtld_rule:
        tldrule_parts = urllib.parse.urlsplit(args.localtld_rule)
        if not tldrule_parts.scheme or not tldrule_parts.netloc:
            # It's not an URL, deal it as local file
            with open(args.localtld_rule, "r", encoding="utf-8") as f:
                localtld_rule = f.read()
        else:
            # Yeah, it's an URL, try to download it
            print("Downloading local tlds rules file from %s" % args.user_rule)
            localtld_rule = (
                urllib.request.urlopen(args.localtld_rule, timeout=10)
                .read()
                .decode("utf-8")
            )
        localtld_rule = localtld_rule.splitlines(False)
    else:
        localtld_rule = []

    cidrs = generate_cnip_cidrs()

    # domains = reduce_domains(domains)
    pac_content = generate_pac_fast(user_rule, args.proxy, direct_rule, cidrs, localtld_rule)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(pac_content)


if __name__ == "__main__":
    main()


# 添加接口
# pip install fastapi uvicorn
# python -m uvicorn gfw-pac:app --reload --host 0.0.0.0 --port 8089
from fastapi import FastAPI, Response

app = FastAPI()


# 从 https://pac.duyao.de/https/us.erl.re/443/ 这样得请求里解析出来 代理协议、代理IP、代理端口
# api 启动命令：python -m uvicorn gfw-pac:app --reload --host 0.0.0.0 --port 8089
@app.get("/{proxy_protocol}/{proxy_ip}/{proxy_port}")
def proxy(proxy_protocol: str, proxy_ip: str, proxy_port: str):
    """
    :param proxy_protocol: 代理协议
    :param proxy_ip: 代理IP
    :param proxy_port: 代理端口

    :return: 修改好代理协议IP端口得 pac 内容
    """

    global gfwlist_url

    args = {
        "output": f"pac/{proxy_protocol}_{proxy_ip}_{proxy_port}.pac",
        "proxy": f"{proxy_protocol} {proxy_ip}:{proxy_port}; ",
        "user_rule": "custom-domains.txt",
        "direct_rule": "direct-domains.txt",
        "localtld_rule": "local-tlds.txt",
    }

    # 设置 args
    import sys

    sys.argv = [
        "gfw-pac.py",
        "-f",
        args["output"],
        "-p",
        args["proxy"],
        "--user-rule",
        args["user_rule"],
        "--direct-rule",
        args["direct_rule"],
        "--localtld-rule",
        args["localtld_rule"],
    ]

    args = parse_args()
    print("args = ", args)

    # 如果本地有这个代理地址的配置文件，那么就用本地的
    # 先检查 pac 目录是否存在
    import os, time

    if not os.path.exists("pac"):
        os.mkdir("pac")
    # 检查 pac 文件是否存在，如果存在，而且修改时间小于1分钟，那么就直接返回
    if os.path.exists(args.output) and (
        os.path.getmtime(args.output) + 60 > time.time()
    ):
        # 存在就直接返回
        with open(args.output, "r", encoding="utf-8") as f:
            return f.read()

    print("Downloading gfwlist from %s" % gfwlist_url)
    content = urllib.request.urlopen(gfwlist_url, timeout=10).read().decode("utf-8")

    # 如果 args["user_rule"] 是本地文件，那么直接读取，否则下载
    with open(args.user_rule, "r", encoding="utf-8") as f:
        user_rule = f.read()

    # 如果 args["direct_rule"] 是本地文件，那么直接读取，否则下载
    with open(args.direct_rule, "r", encoding="utf-8") as f:
        direct_rule = f.read()
    direct_rule = direct_rule.splitlines(False)

    # 如果 args["localtld_rule"] 是本地文件，那么直接读取，否则下载
    with open(args.localtld_rule, "r", encoding="utf-8") as f:
        localtld_rule = f.read()
    localtld_rule = localtld_rule.splitlines(False)

    cnips = fetch_ip_data()

    content = decode_gfwlist(content)
    gfwlist = combine_lists(content, user_rule)

    domains = parse_gfwlist(gfwlist)
    # domains = reduce_domains(domains)
    pac_content = generate_pac_fast(
        domains, args.proxy, direct_rule, cnips, localtld_rule
    )

    print("pac_content = ", type(pac_content))

    # 存到本地，下次就不用再生成了
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(pac_content)

    # 直接返回 raw pac 内容
    return Response(content=pac_content.strip('"'), media_type="application/x-ns-proxy-autoconfig")
