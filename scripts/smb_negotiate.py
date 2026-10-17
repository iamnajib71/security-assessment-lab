"""Minimal credential-free SMB2 negotiation against fixed host loopback 1445.

Read the server's actual signing-required bit. smbclient's signing=disabled is
only a client preference in this image and still honors mandatory server signing.
"""
import json
import secrets
import socket
import struct


def signing_policy():
    header = struct.pack('<4sHHIHHIIQIIQ16s', b'\xfeSMB', 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, bytes(16))
    body = struct.pack('<HHHHI16sIHH', 36, 2, 1, 0, 0, secrets.token_bytes(16), 0, 0, 0)
    packet = header + body + struct.pack('<HH', 0x0202, 0x0210)
    def recv_exact(sock, count):
        result = b''
        while len(result) < count:
            data = sock.recv(count-len(result))
            if not data: raise RuntimeError('Truncated SMB response')
            result += data
        return result
    with socket.create_connection(('127.0.0.1', 1445), timeout=5) as sock:
        sock.sendall(len(packet).to_bytes(4, 'big') + packet)
        length = int.from_bytes(recv_exact(sock, 4), 'big')
        if length > 65536: raise RuntimeError('Unexpected SMB response size')
        response = recv_exact(sock, length)
    if response[:4] != b'\xfeSMB' or len(response) < 70:
        raise RuntimeError('Invalid SMB2 negotiate response')
    status = struct.unpack_from('<I', response, 8)[0]
    if status: raise RuntimeError(f'SMB negotiation status {status:#x}')
    mode, dialect = struct.unpack_from('<HH', response, 66)
    return {'target': '127.0.0.1:1445', 'security_mode': mode, 'dialect': hex(dialect),
            'signing_enabled': bool(mode & 1), 'signing_required': bool(mode & 2),
            'request_hex': packet.hex(), 'response_hex': response.hex()}


if __name__ == '__main__': print(json.dumps(signing_policy(), indent=2))
