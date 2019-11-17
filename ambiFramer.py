import pytaps as taps
import argparse
import asyncio

color="blue"

class AmbiFramer(taps.Framer):
    def __init__(self, remote_endpoint, security_parameters=None, local_endpoint=None):
        self.remote_endpoint = remote_endpoint
        self.local_endpoint = local_endpoint
        self.preconnection = None
        self.connection = None
    
    async def handle_received_partial(self, data, context, end_of_message,
                                      connection):
        taps.print_time("Received partial message " + str(data) + ".", color)
        await self.connection.receive(min_incomplete_length=1)

    async def handle_received(self, data, context, connection):
        taps.print_time("Received message " + str(data) + ".", color)
        await self.connection.receive(min_incomplete_length=1)
    
    async def handle_ready(self, connection):
        print("Connection ready")
        msgref = await self.connection.receive()
        self.connection.on_received_partial(self.handle_received_partial)
        self.connection.on_received(self.handle_received)
        await self.connection.receive(min_incomplete_length=1)

    async def start(self, connection):
        
        tp = taps.TransportProperties()
        self.preconnection = taps.Preconnection(remote_endpoint=self.remote_endpoint, local_endpoint=self.local_endpoint, transport_properties=tp)
        self.preconnection.on_ready(self.handle_ready)
        self.connection = await self.preconnection.initiate()

class AmbiClient():
    def __init__(self, args):
        self.listener = None
        self.preconnection = None
        self.loop = asyncio.get_event_loop()
        self.args = args

    async def main(self):
        mcg = taps.LocalEndpoint()
        mcg.with_address(args.group_address)
        mcg.with_port(args.group_port)
        ssm = taps.RemoteEndpoint()
        ssm.with_address(args.ssm_address)
        ssm.with_port(args.ssm_port)

        rambi = taps.RemoteEndpoint()
        rambi.with_address([args.remote_ambi_address])
        rambi.with_port(args.remote_ambi_port)
        if args.local_ambi_address is not None:
            lambi = taps.LocalEndpoint()
            lambi.with_address(args.local_ambi_address)
            lambi.with_port(args.local_ambi_port)
        else:
            lambi = None

        tp = taps.TransportProperties()
        tp.add("direction", "unidirection-receive")
        tp.prohibit("reliability")
        tp.ignore("congestion-control")
        tp.ignore("preserve-order")

        self.preconnection = taps.Preconnection(remote_endpoint=ssm,
                                                local_endpoint=mcg,
                                                transport_properties=tp)
        
        ambi = AmbiFramer(remote_endpoint = rambi, local_endpoint= lambi)
        self.preconnection.add_framer(ambi)
        self.listener = await self.preconnection.listen()
        print(self.listener.local_endpoint.port)

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
