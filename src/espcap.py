#!/usr/bin/env python

""" espcap.py

Network packet capture and indexing with Elasticsearch

Copyright (c) 2019 Vic Hargrave

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
"""

import syslog
import os
import sys
import click

from elasticsearch import Elasticsearch
from elasticsearch import helpers

from tshark import Tshark
from indexer import index_packets, dump_packets

def init_live_capture(es, tshark, nic, bpf, chunk, count):
    """ Set up for live packet capture.

    :param es: Elasticsearch cluster handle, None if packets are dumped to stdout
    :param tshark: Tshark instance
    :param indexer: Indexer instance
    :param nic: Network interface
    :param bpf: Packet filter expression
    :param chunk: Number of packets to index in Elasticsearch at a time.
    :param count: Number of packets to capture, 0 if capturing indefinitely,
    """
    try:
        command = tshark.make_command(nic=nic, count=count, bpf=bpf, pcap_file=None, interfaces=False)
        capture = tshark.capture(command)
        if es is None:
            dump_packets(capture)
        else:
            helpers.bulk(client=es, actions=index_packets(capture=capture), chunk_size=chunk, raise_on_error=True)

    except Exception as e:
        print('[ERROR] ', e)
        syslog.syslog(syslog.LOG_ERR, e)
        sys.ext(1)


def init_file_capture(es, tshark, pcap_files, chunk):
    """ Set up for file packet capture.

    :param es: Elasticsearch cluster handle, None if packets are dumped to stdout
    :param tshark: Tshark instance
    :param indexer: Indexer instance
    :param pcap_files: PCAP input file from where packets are read.
    :param chunk: Number of packets to index in Elasticsearch at a time.
    """
    try:
        print('Loading packet capture file(s)')
        for pcap_file in pcap_files:
            command = tshark.make_command(nic=None, count=0, bpf=None, pcap_file=pcap_file, interfaces=None)
            print(pcap_file)
            capture = tshark.capture(command)
            if es is None:
                dump_packets(capture)
            else:
                helpers.bulk(client=es, actions=index_packets(capture=capture), chunk_size=chunk, raise_on_error=True)

    except Exception as e:
        print('[ERROR] ', e)
        syslog.syslog(syslog.LOG_ERR, e)
        sys.ext(1)


@click.command()
@click.option('--node', default=None, help='Elasticsearch IP and port (default=None, dump packets to stdout)')
@click.option('--nic', default=None, help='Network interface for live capture (default=None, if file or dir specified)')
@click.option('--file', default=None, help='PCAP file for file capture (default=None, if nic specified)')
@click.option('--dir', default=None, help='PCAP directory for multiple file capture (default=None, if nic specified)')
@click.option('--bpf', default=None, help='Packet filter for live capture (default=all packets)')
@click.option('--chunk', default=1000, help='Number of packets to bulk index (default=1000)')
@click.option('--count', default=0, help='Number of packets to capture during live capture (default=0, capture indefinitely)')
@click.option('--list', is_flag=True, help='Lists the network interfaces')
def main(node, nic, file, dir, bpf, chunk, count, list):
    try:
        tshark = Tshark()
        tshark.set_interrupt_handler()

        es = None
        if node is not None:
            es = Elasticsearch(node)

        if list:
            command = tshark.make_command(nic=None, count=0, bpf=None, pcap_file=None, interfaces=True)
            tshark.list_interfaces(command)
            sys.exit(0)

        if nic is None and file is None and dir is None:
            print('You must specify either file or live capture')
            sys.exit(1)

        if nic is not None and (file is not None or dir is not None):
            print('You cannot specify file and live capture at the same time')
            sys.exit(1)

        syslog.syslog("espcap started")

        if nic is not None:
            init_live_capture(es=es, tshark=tshark, nic=nic, bpf=bpf, chunk=chunk, count=count)

        elif file is not None:
            pcap_files = []
            pcap_files.append(file)
            init_file_capture(es=es, tshark=tshark, pcap_files=pcap_files, chunk=chunk)

        elif dir is not None:
            pcap_files = []
            files = os.listdir(dir)
            files.sort()
            for file in files:
                pcap_files.append(dir+'/'+file)
            init_file_capture(es=es, tshark=tshark, indexer=indexer, pcap_files=pcap_files, chunk=chunk)

    except Exception as e:
        print('[ERROR] ', e)
        syslog.syslog(syslog.LOG_ERR, e)
        sys.exit(1)


if __name__ == '__main__':
    main()
    print('Done')
