#!/usr/bin/env python3
import socket
import struct
import time
import select
import os
import sys
import math

ICMP_ECHO_REQUEST = 8
JITTER_ALPHA = 1 / 8


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'

    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]

    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class ICMPProbeAgent:
    def __init__(self, dst_ip, iface=None, timeout=1.0):
        self.dst_ip = dst_ip
        self.iface = iface
        self.timeout = timeout

        self.id = os.getpid() & 0xFFFF
        self.seq = 0

        # Métricas
        self.sent = 0
        self.received = 0
        self.last_rtt = None
        self.rtt_min = None
        self.jitter = 0.0

        self.sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_ICMP
        )

        if iface:
            self.sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                iface.encode()
            )

        self.sock.settimeout(timeout)

    def build_packet(self):
        self.seq += 1

        header = struct.pack(
            "!BBHHH",
            ICMP_ECHO_REQUEST,
            0,
            0,
            self.id,
            self.seq
        )

        payload = struct.pack("!d", time.time())
        chksum = checksum(header + payload)

        header = struct.pack(
            "!BBHHH",
            ICMP_ECHO_REQUEST,
            0,
            chksum,
            self.id,
            self.seq
        )

        return header + payload

    def send_probe(self):
        packet = self.build_packet()
        self.sock.sendto(packet, (self.dst_ip, 1))
        self.sent += 1
        return self.seq

    def receive_reply(self):
        start = time.time()

        while True:
            remaining = self.timeout - (time.time() - start)
            if remaining <= 0:
                return None

            r, _, _ = select.select([self.sock], [], [], remaining)
            if not r:
                return None

            packet, _ = self.sock.recvfrom(1024)
            icmp_header = packet[20:28]

            icmp_type, _, _, pkt_id, seq = struct.unpack(
                "!BBHHH", icmp_header
            )

            if icmp_type == 0 and pkt_id == self.id:
                payload = packet[28:36]
                tx_time = struct.unpack("!d", payload)[0]
                rtt = (time.time() - tx_time) * 1000.0
                return seq, rtt

    def update_metrics(self, rtt):
        self.received += 1

        # RTT mínimo
        if self.rtt_min is None or rtt < self.rtt_min:
            self.rtt_min = rtt

        # Jitter (EWMA)
        if self.last_rtt is not None:
            delta = abs(rtt - self.last_rtt)
            self.jitter += JITTER_ALPHA * (delta - self.jitter)

        self.last_rtt = rtt

        # Bufferização
        buffering = rtt - self.rtt_min if self.rtt_min else 0.0

        return buffering

    def loss_rate(self):
        if self.sent == 0:
            return 0.0
        return (self.sent - self.received) / self.sent * 100.0

    def probe_once(self):
        seq = self.send_probe()
        reply = self.receive_reply()

        if reply is None:
            return seq, None, None

        _, rtt = reply
        buffering = self.update_metrics(rtt)
        return seq, rtt, buffering


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <destino> [interface]")
        sys.exit(1)

    dst = sys.argv[1]
    iface = sys.argv[2] if len(sys.argv) > 2 else None

    agent = ICMPProbeAgent(dst, iface=iface)

    print(f"🔎 Probing {dst} via {iface or 'default'}")
    print("seq  RTT(ms)  jitter(ms)  buffering(ms)  loss(%)")

    try:
        while True:
            seq, rtt, buffering = agent.probe_once()

            if rtt is None:
                print(f"{seq:3d}  timeout                        {agent.loss_rate():6.2f}")
            else:
                print(
                    f"{seq:3d}  "
                    f"{rtt:7.2f}  "
                    f"{agent.jitter:10.2f}  "
                    f"{buffering:13.2f}  "
                    f"{agent.loss_rate():6.2f}"
                )

            time.sleep(1)

    except KeyboardInterrupt:
        print("\n--- Estatísticas finais ---")
        print(f"Enviados: {agent.sent}")
        print(f"Recebidos: {agent.received}")
        print(f"Perda: {agent.loss_rate():.2f}%")
        if agent.last_rtt:
            print(f"RTT médio aprox.: {agent.last_rtt:.2f} ms")
            print(f"RTT mínimo: {agent.rtt_min:.2f} ms")
            print(f"Jitter EWMA: {agent.jitter:.2f} ms")
