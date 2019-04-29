""" tshark.py

Wrapper API class for tshark

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

import signal
import subprocess
import sys
import os
import yaml
import json

closing = False

# Sets flag  to stop capture when the current packet is processed.
def _exit_gracefully(signum, frame):
    """ Sets global closing flag.

    :param signum: Signal type
    :param frame:
    """
    global closing
    closing = True


class Tshark(object):
    _command = list()
    _config_paths = ['espcap.yml','../config/espcap.yml','/etc/espcap/espcap.yml']

    def __init__(self):
        """ Sets the path to tshark.  Try all the possible paths in _config_paths
        """
        config = None
        for config_path in self._config_paths:
            if os.path.isfile(config_path):
                with open(config_path, 'r') as ymlconfig:
                    config = yaml.load(ymlconfig, Loader=yaml.FullLoader)
                self._command.append(config['tshark_path'])
                return
        print("Could not find configuration file")
        sys.exit(1)

    def file_capture(self, pcap_file):
        """ Generator to do file capture.

        :param pcap_file: PCAP file
        :return: Packet JSON object that can be indexed in Elasticsearch
        """
        global closing
        command = self._make_command(nic=None, count=0, bpf=None, pcap_file=pcap_file, interfaces=None)
        with subprocess.Popen(command, stdout=subprocess.PIPE, bufsize=1) as proc:
            for packet in proc.stdout:
                packet = self._filter_line(packet)
                if packet is None:
                    continue
                else:
                    yield json.loads(packet)

            if closing is True:
                print('Capture interrupted')
                sys.exit()

    def live_capture(self, nic, count, bpf):
        """ Generator to do live capture.

        :param nic: Network interface
        :param count: Number of packets to capture, 0 capture indefinitely
        :param bpf: Packet filter expressions
        :return: Packet JSON object that can be indexed in Elasticsearch
        """
        global closing
        command = self._make_command(nic=nic, count=count, bpf=bpf, pcap_file=None, interfaces=False)
        with subprocess.Popen(command, stdout=subprocess.PIPE, bufsize=1) as proc:
            for packet in proc.stdout:
                packet = self._filter_line(packet)
                if packet is None:
                    continue
                else:
                    yield json.loads(packet)

            if closing is True:
                print('Capture interrupted')
                sys.exit()

    # List all the network interfaces available
    def list_interfaces(self):
        """ Get all the network interfaces available.

        :return: List of network interfaces
        """
        command = self._make_command(nic=None, count=None, bpf=None, pcap_file=None, interfaces=True)
        with subprocess.Popen(command, stdout=subprocess.PIPE, bufsize=1) as proc:
            for interface in proc.stdout:
                print(interface.decode().rstrip('\n'))

    # What to do when the application is interrupted.
    def set_interrupt_handler(self):
        """ Set interrupt handlers """
        signal.signal(signal.SIGTERM, _exit_gracefully)
        signal.signal(signal.SIGINT, _exit_gracefully)

    def _filter_line(self, line):
        """ Drops the bulk index line from the tshark packet output

        :param line: Line with extra characters
        :return: Line minus the extra characters
        """
        decoded_line = line.decode().rstrip('\n')
        if decoded_line.startswith('{\"index\":') is True:
            return None
        else:
            return decoded_line

    # Builds the tshark command with arguments.
    def _make_command(self, nic, count, bpf, pcap_file, interfaces):
        """ Builds a tshark command to execute.

        :param nic: Network interface
        :param count: Number of packets to capture, 0 if capturing indefinitely
        :param bpf: Packet filter expression
        :param pcap_file: PCAP file where packets are coming from, None if live capture
        :param interfaces: -D if just getting a list of network interfaces
        :return: tshark with arguments array
        """
        command = self._command

        if interfaces is True:
            command.append('-D')
            return command

        command.append('-T')
        command.append('ek')
        if nic is not None:
            command.append('-i')
            command.append(nic)
        if count != 0:
            command.append('-c')
            command.append(str(count))
        if bpf is not None:
            elements = bpf.split()
            for element in elements:
                command.append(element)
        if pcap_file is not None:
            command.append('-r')
            command.append(pcap_file)

        return command
