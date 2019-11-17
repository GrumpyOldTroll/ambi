import asyncio
import sys
import argparse
import ipaddress
import re
import json
import pytaps as taps  # noqa: E402
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import struct
import datetime

color = "yellow"
layout = '''
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Source Address (32 bits IPv4/128 bits IPv6)           |
   |                             ...                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Destination Address (32 bits IPv4/128 bits IPv6)        |
   |                             ...                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Zeroes    |   Protocol    |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |        Destination Port       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Manifest Identifier                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Payload Data                           |
   |                             ...                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+'''

class ManifestHasher(object):
    def __init__(self, source, dest, dest_port, hash_alg, manifest_id):
        self.manifest_id = manifest_id
        self.hash_alg = hash_alg
        self.digest_base = hashes.Hash(hash_alg, backend=default_backend())
        self.digest_base.update(source.packed)
        self.digest_base.update(dest.packed)
        self.digest_base.update(struct.pack('BB', 0, 17))
        self.dest_port = dest_port

    def digest(self, data, source_port):
        dig = self.digest_base.copy()
        hdr_tail = struct.pack('HHHI', len(data), source_port,
                self.dest_port, self.manifest_id)
        dig.update(hdr_tail)
        dig.update(data)
        return dig.finalize()

manifest_layout='''
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  Manifest Stream Identifier                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   Manifest sequence number                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 First packet sequence number                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Refresh Deadline        |      Packet Digest Count      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 ... Packet Content Expansions ...             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      ... Packet Digests ...                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+'''
class ManifestBuilder(object):
    def __init__(self, hasher, packet_limit=100, time_limit=2):
        self.manifest_id = hasher.manifest_id
        self.hasher = hasher
        self.manifest_seq = 1
        self.packet_seq = 1
        self.cur_hashes = []
        self.last_wrote = datetime.datetime.now()
        self.time_limit = None
        if time_limit:
            self.time_limit = datetime.timedelta(seconds=time_limit)
        self.packet_limit = packet_limit
        self.sender = None
        self.loop = asyncio.get_event_loop()

    def got_packet(self, data, source_port):
        # TBD: handle wrapping
        # TBD: graceful shutdown signal to pick a refresh_deadline
        refresh_deadline = 0
        dig = self.hasher.digest(data, source_port)
        self.cur_hashes.append(dig)
        self.packet_seq += 1
        if len(self.cur_hashes) < self.packet_limit:
            if not self.time_limit:
                return
            since = datetime.datetime.now() - self.last_wrote
            if since < self.time_limit:
                return

        manifest = struct.pack('IIIHH', self.manifest_id,
                self.manifest_seq, self.packet_seq - len(self.cur_hashes),
                refresh_deadline, len(self.cur_hashes))
        manifest += b''.join(self.cur_hashes)
        if self.sender:
            taps.print_time("New manifest pushing (%d conns)" % len(self.sender.connections), color)
            self.loop.create_task(self.sender.push_new_manifest(manifest))
        else:
            taps.print_time("New manifest without sender)",
                color)
        self.last_wrote = datetime.datetime.now()
        self.cur_hashes = []
        self.manifest_seq += 1


# map from names in hash-algorithm-t in
# https://tools.ietf.org/html/draft-ietf-netconf-crypto-types-11
# to options from cryptography.hazmat.primitives import hashes
HASH_ALG_MAP = {
        'sha-224': hashes.SHA3_224,
        'sha-256': hashes.SHA3_256,
        'sha-384': hashes.SHA3_384,
        'sha-512': hashes.SHA3_512,
        'shake-128': hashes.SHAKE128(16),
        # 'shake-224': hashes.SHAKE256(28),  # TBD: is this right?
        'shake-256': hashes.SHAKE256(32),
    }

class ManifestServer(object):
    def __init__(self, addr, port, trust_ca, local_identity):
        self.preconnection = None
        self.addr = addr
        self.port = port
        self.trust_ca = trust_ca
        self.local_identity = local_identity
        self.loop = asyncio.get_event_loop()
        self.connections = []

    async def push_new_manifest(self, manifest):
        for conn in self.connections:
            self.loop.create_task(conn.send_message(manifest))

    async def handle_connection_received(self, connection):
        taps.print_time("Received new Connection.", color)
        self.connections.append(connection)
        connection.on_sent(self.handle_sent)
        connection.on_closed(self.handle_closed)
        # TBD jake 2019-11-17: http framer
        # - inbound request for application/ambi
        # - outbound: response header, then chunked encoding per manifest
        # self.connection.on_received_partial(self.handle_received_partial)
        # self.connection.on_received(self.handle_received)
        # await self.connection.receive(min_incomplete_length=4, max_length=3)

    async def handle_listen_error(self):
        taps.print_time("Listen Error occured.", color)
        self.loop.stop()

    async def handle_sent(self, message_ref, connection):
        taps.print_time("Sent cb received, message " + str(message_ref) +
                        " has been sent.", color)

    async def handle_stopped(self):
        taps.print_time("Listener has been stopped")

    async def handle_closed(self, connection):
        taps.print_time("Connection closed.", color)
        for idx, conn in zip(range(len(self.connections)), self.connections):
            if conn is connection:
                break
        if idx < len(self.connections):
            del self.connections[idx]
        # self.loop.stop()

    async def main(self):
        yang_data = {
              "ietf-taps-api:preconnection":{
                "local-endpoints":[
                  {
                    "id":"1",
                    "local-address":str(self.addr),
                    "local-port":str(self.port),
                  }
                ]
              }
            }

        self.preconnection = taps.Preconnection.from_yang(taps.yang_validate.YANG_FMT_JSON, json.dumps(yang_data, indent=4));

        if self.trust_ca or self.local_identity:
            sp = taps.SecurityParameters()
            if self.trust_ca:
                sp.addTrustCA(self.trust_ca)
            if self.local_identity:
                sp.addIdentity(self.local_identity)
            self.preconnection.security_parameters = sp

        self.preconnection.on_connection_received(
                self.handle_connection_received)
        self.preconnection.on_listen_error(self.handle_listen_error)
        self.preconnection.on_stopped(self.handle_stopped)
        await self.preconnection.listen()


class AmbiListener(object):
    def __init__(self, source, group, port, manifestid, algorithm):
        global HASH_ALG_MAP
        self.listener = None
        self.connections = []
        self.preconnection = None
        self.loop = asyncio.get_event_loop()
        self.source = ipaddress.ip_address(source)
        self.group = ipaddress.ip_address(group)
        self.port = int(port)
        self.yang_data = {
              "ietf-taps-api:preconnection":{
                "local-endpoints":[
                  {
                    "id":"1",
                    "local-address":str(self.group),
                    "local-port":str(self.port),
                  }
                ],
                "remote-endpoints":[
                  {
                    "id":"1",
                    "remote-host":str(self.source),
                  }
                ],
                "transport-properties": {
                  "direction":"unidirection-receive",
                  "congestion-control":"ignore",
                  "reliability":"prohibit",
                  "preserve-order":"ignore"
                }
              }
            }
        self.packet_seq = 0
        self.cur_manifest = None
        hash_alg = HASH_ALG_MAP[algorithm]
        self.manifest_hasher = ManifestHasher(source=self.source,
                dest=self.group, dest_port=self.port, hash_alg=hash_alg,
                manifest_id=manifestid)
        self.manifest_builder = ManifestBuilder(self.manifest_hasher)

    async def handle_connection_received(self, connection):
        self.connections.append(connection)
        taps.print_time("Received new Data Connection (%d total)." % len(self.connections), color)
        connection.on_received(self.handle_received)
        # jake 2019-11-16: should handle_closed have the connection object?
        connection.on_closed(self.handle_closed)
        await connection.receive()

    async def handle_received(self, data, context, connection):
        #taps.print_time("Received message " + str(data) + ".", color)
        #print('got msg len=%d' % len(data))
        # self.loop.stop()
        #print(type(connection.remote_endpoint.port))
        #print(connection.remote_endpoint.port)

        self.manifest_builder.got_packet(data=data,
                source_port=int(connection.remote_endpoint.port))
        await connection.receive()

    async def handle_listen_error(self):
        taps.print_time("Listen Error occured.", color)
        self.loop.stop()

    async def handle_stopped(self):
        taps.print_time("Listener has been stopped")

    async def handle_closed(self, conn):
        taps.print_time("Connection closed.", color)
        # self.loop.stop()

    async def main(self):
        self.preconnection = taps.Preconnection.from_yang(taps.yang_validate.YANG_FMT_JSON, json.dumps(self.yang_data, indent=4));

        self.preconnection.on_listen_error(self.handle_listen_error)
        self.preconnection.on_connection_received(self.handle_connection_received)
        taps.print_time("Created preconnection object and set cbs.", color)

        # Initiate the connection
        self.listener = await self.preconnection.listen()
        taps.print_time("Called initiate, connection object created.", color)


if __name__ == "__main__":
    # Parse arguments
    ap = argparse.ArgumentParser(description='AMBI generator.')
    ap.add_argument('--datasource', '-s', help='source ip')
    ap.add_argument('--datagroup', '-g', help='group ip')
    ap.add_argument('--dataport', '-p', type=int, help='UDP port')
    ap.add_argument('--manifestid', '-m', type=int, help='manifest id')
    ap.add_argument('--algorithm', '-a', help='hash algorithm',
            choices=sorted(HASH_ALG_MAP.keys()))
    ap.add_argument('--listen-address', '-l',
            help='listening ip for manifest channel', default='127.0.0.1')
    ap.add_argument('--listen-port', '-o', help='listening port for manifest channel')
    ap.add_argument('--local-identity', '-i', default=None)
    ap.add_argument('--trust-ca', '-t', default=None)
    args = ap.parse_args()
    print(args)
    # Start testclient
    mc_client = AmbiListener(source=args.datasource,
            group=args.datagroup,
            port=args.dataport,
            manifestid=args.manifestid,
            algorithm=args.algorithm)
    manifest_server = ManifestServer(addr=args.listen_address,
            port=args.listen_port, trust_ca=args.trust_ca,
            local_identity=args.local_identity)
    mc_client.manifest_builder.sender = manifest_server

    loop = mc_client.loop
    loop.create_task(mc_client.main())
    loop.create_task(manifest_server.main())
    loop.run_forever()
