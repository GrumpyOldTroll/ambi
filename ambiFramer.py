import pytaps as taps
import argparse
import asyncio
import ipaddress
import struct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from hasher import ManifestHasher
color="blue"
color2="red"

class AmbiFramer(taps.Framer):
    def __init__(self, remote_endpoint, security_parameters=None, local_endpoint=None):
        self.remote_endpoint = remote_endpoint
        self.local_endpoint = local_endpoint
        self.preconnection = None
        self.connection = None
        self.hasher = None
        self.source = None
        self.group = None
        self.group_port = None
        self.manifest_id = 15
        self.hashes = []
    
    async def handle_received_partial(self, data, context, end_of_message,
                                      connection):
        manifest = struct.unpack_from('IIIHH', data)
        self.manifest_id = int(manifest[0])
        hashes = data[16:]
        len_hashes = int(len(hashes)/manifest[4])
        while(len(hashes) > 0):
            self.hashes.append(hashes[:len_hashes])
            hashes = hashes[len_hashes:]

        await self.connection.receive(min_incomplete_length=1)

    async def handle_received(self, data, context, connection):
        taps.print_time("Received manifest " + str(data) + ".", color2)
        await self.connection.receive(min_incomplete_length=1)
    
    async def handle_ready(self, connection):
        taps.print_time("TCP connection ready", color2)
        self.connection.on_received_partial(self.handle_received_partial)
        self.connection.on_received(self.handle_received)
        await self.connection.receive(min_incomplete_length=1)

    async def handle_received_data(self, connection):
        self.hasher = ManifestHasher(self.source, self.group, self.group_port,hashes.SHAKE128(16),self.manifest_id)
        stream, context, eom =connection.parse()
        if len(stream) == 0:
            raise taps.DeframingFailed
            return
        timeout = 0
        msg = stream[0]
        hash = self.hasher.digest(msg, connection.remote_endpoint.port)
        while(timeout <= 2):
            if hash in self.hashes:
                    self.hashes.remove(hash)
                    return (None,msg,1,True)
            else:
                await asyncio.sleep(0.1)
                timeout+= 0.1
        raise taps.DeframingFailed
        return

    async def start(self, connection):
        
        # Set the parameters required for Manifest hashing
        self.source = ipaddress.ip_address(connection.remote_endpoint.address[0])
        self.group = ipaddress.ip_address(connection.local_endpoint.address[0])
        self.group_port = connection.local_endpoint.port

        # Create new transport properties, since we want a TCP (TLS) conenction, the defaults are fine
        tp = taps.TransportProperties()
        # Create a new preconnection, set the ready callback and initiate it
        self.preconnection = taps.Preconnection(remote_endpoint=self.remote_endpoint, local_endpoint=self.local_endpoint, transport_properties=tp)
        self.preconnection.on_ready(self.handle_ready)
        self.connection = await self.preconnection.initiate()


class AmbiClient():
    def __init__(self, args):
        self.listener = None
        self.preconnection = None
        self.connection = None
        self.loop = asyncio.get_event_loop()
        self.args = args

    async def handle_received(self, data, context, connection):
        taps.print_time("Received multicast message " + str(data) + ".", color)
        await self.connection.receive()

    async def handle_connection_received(self, connection):
        self.connection = connection
        # Set the received callback
        self.connection.on_received(self.handle_received)
        # Queue the reception of a message on the connection
        await self.connection.receive()


    async def main(self):
        # Create (local) multicast group endpoint
        mcg = taps.LocalEndpoint()
        mcg.with_address(args.group_address)
        mcg.with_port(args.group_port)

        # Create (remote) source endpoint
        ssm = taps.RemoteEndpoint()
        ssm.with_address(args.ssm_address)
        ssm.with_port(args.ssm_port)

        # Create endpoint for the remote for AMBI
        rambi = taps.RemoteEndpoint()
        rambi.with_address(args.remote_ambi_address)
        rambi.with_port(args.remote_ambi_port)

        # Create endpoint for the local for AMBI
        if args.local_ambi_address is not None:
            lambi = taps.LocalEndpoint()
            lambi.with_address(args.local_ambi_address)
            lambi.with_port(args.local_ambi_port)
        else:
            lambi = None

        # Set the transportpropterties necessary to get a multicast stream
        tp = taps.TransportProperties()
        tp.add("direction", "unidirection-receive")
        tp.prohibit("reliability")
        tp.ignore("congestion-control")
        tp.ignore("preserve-order")

        # Configure the preconnection
        self.preconnection = taps.Preconnection(remote_endpoint=ssm,
                                                local_endpoint=mcg,
                                                transport_properties=tp)
        
        # Set the new connection callback
        self.preconnection.on_connection_received(self.handle_connection_received)
        # Create a new AMBI framer object and set it on the preconnection.
        ambi = AmbiFramer(remote_endpoint = rambi, local_endpoint= lambi)
        self.preconnection.add_framer(ambi)
        # Initiate the preconnection so it can start to received multicast packets
        self.listener = await self.preconnection.listen()

if __name__ == "__main__":
    # Parse arguments
    ap = argparse.ArgumentParser(description='PyTAPS AMBI client.')
    ap.add_argument('--ssm-address', '--source-address', default=None)
    ap.add_argument('--ssm-port', '--source-port', type=int, default=6666)
    ap.add_argument('--group-address', '-g', default=None)
    ap.add_argument('--group-port', type=int, default=5678)
    ap.add_argument('--remote-ambi-address', '-a', default=None)
    ap.add_argument('--remote-ambi-port', type=int, default=9456)
    ap.add_argument('--local-ambi-address', '-l', default=None)
    ap.add_argument('--local-ambi-port', type=int, default=9456)
    ap.add_argument('--trust-ca', type=str, default=None)
    ap.add_argument('--secure', '-s', nargs='?', const=True,
                    type=bool, default=False)
    args = ap.parse_args()
    print(args)
    # Start ambiClient
    client = AmbiClient(args)
    client.loop.create_task(client.main())
    client.loop.run_forever()
