#!/usr/bin/python
# Copyright [2019-2022] Universidade Federal do Espirito Santo
#                       Instituto Federal do Espirito Santo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# TOPOLOGIA COM 2 SWITCHES CORE, 1 EDGE(POLKA) E 2 HOSTS
# H1 (Polka-eBPF) ---- S1 ----------- S2 ---- (Polka-eBPF) H2
#                        \ __ S3 __ /
import os
import sys

from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.bmv2 import P4Switch
from mininet.term import makeTerm
from mininet.node import RemoteController

import subprocess
from subprocess import run

n_switches = 3
BW = 10

#########################################################################
################ DELETA AS INFERFACES CRIADAS ###########################
#########################################################################
def limpa_int():
	os.system("sudo mn -c")
	interfaces = ["h1-eth0","h2-eth0","s1-eth1","s1-eth2","s1-eth3","s2-eth1","s2-eth2","s2-eth3","s3-eth1","s3-eth2"]
	for interface in interfaces:
		subprocess.run(["sudo","ip","link","delete", interface])


def topology(remote_controller):
    "Create a network."
    net = Mininet()

    # linkopts = dict()
    switches = []
    edges = []
    hosts = []

    info("*** Adding hosts\n")
    # for i in range(1, n_switches + 1):
    for i in range(1, n_switches):
        ip = "10.0.%d.%d" % (i, i)
        mac = "00:00:00:00:%02x:%02x" % (i, i)
        host = net.addHost("h%d" % i, ip=ip, mac=mac)
        hosts.append(host)

    info("*** Adding P4Switches (core)\n")
    for i in range(1, n_switches + 1):
        # read the network configuration
        path = os.path.dirname(os.path.abspath(__file__))
        json_file = path + "/polka/polka-core.json"
        config = path + "/polka/config/s{}-commands.txt".format(i)
        # Add P4 switches (core)
        switch = net.addSwitch(
            "s{}".format(i),
            netcfg=True,
            json=json_file,
            thriftport=50000 + int(i),
            switch_config=config,
            loglevel='debug',
            cls=P4Switch,
        )
        switches.append(switch)

 
    info("*** Conecting hosts to edge switches ...\n")
    net.addLink(hosts[0], switches[0], bw=BW)
    net.addLink(hosts[1], switches[1], bw=BW)

    info("*** Creating path 01 ...\n")
    net.addLink(switches[0], switches[1], bw=BW, stp=True)

    info("*** Creating path 02 ...\n")
    net.addLink(switches[0], switches[2], bw=BW, stp=True)
    net.addLink(switches[2], switches[1], bw=BW, stp=True)


    info("*** Starting network\n")
    net.start()
    net.staticArp()

    # disabling offload for rx and tx on each host interface
    for host in hosts:
        host.cmd("ethtool --offload {}-eth0 rx off tx off".format(host.name))
        host.cmd("./conf-{}-map.sh".format(host.name))
        host.cmd("sh < conf/{}-table.txt".format(host.name))

    info("*** Running CLI\n")
    CLI(net)

    os.system("pkill -9 -f 'xterm'")

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    limpa_int()
    remote_controller = False
    topology(remote_controller)
