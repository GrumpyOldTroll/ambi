from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import struct

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

