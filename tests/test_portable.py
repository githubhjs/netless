import os
import pathlib
import socket
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / "build" / "netless"


class PortableSandboxTests(unittest.TestCase):
    def run_child(self, source):
        with tempfile.NamedTemporaryFile("w", suffix=".py") as script:
            script.write(source)
            script.flush()
            return subprocess.run([str(BIN), "--", "python3", script.name],
                                  capture_output=True, text=True)

    def test_network_bind_is_blocked(self):
        code = "import socket\nfor name in ['AF_INET','AF_INET6']:\n try:\n  s=socket.socket(getattr(socket,name)); s.bind(('127.0.0.1',0) if name=='AF_INET' else ('::1',0)); print('BAD')\n except OSError: print('blocked')\n"
        p = self.run_child(code)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.splitlines(), ["blocked", "blocked"])

    def test_outbound_tcp_udp_and_raw_socket_attempts_are_blocked(self):
        code = """import socket
checks = [
    ('tcp4', socket.AF_INET, socket.SOCK_STREAM, ('1.1.1.1', 443)),
    ('udp4', socket.AF_INET, socket.SOCK_DGRAM, ('8.8.8.8', 53)),
    ('tcp6', socket.AF_INET6, socket.SOCK_STREAM, ('2606:4700:4700::1111', 443, 0, 0)),
]
for name, family, kind, address in checks:
    s = None
    try:
        s = socket.socket(family, kind)
        if kind == socket.SOCK_STREAM: s.settimeout(2); s.connect(address)
        else: s.sendto(b'netless-probe', address)
        print(name + ':ALLOWED')
    except OSError: print(name + ':blocked')
    finally:
        try: s.close()
        except (OSError, AttributeError): pass
try:
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    print('raw:ALLOWED')
except OSError: print('raw:blocked')
"""
        p = self.run_child(code)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.splitlines(), ["tcp4:blocked", "udp4:blocked", "tcp6:blocked", "raw:blocked"])

    def test_dns_lookup_cannot_open_network_socket(self):
        p = self.run_child("import socket\ntry: socket.getaddrinfo('example.com',80); print('BAD')\nexcept OSError: print('blocked')\n")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "blocked")

    def test_restriction_is_inherited_by_exec_child(self):
        p = self.run_child("import subprocess,sys\nr=subprocess.run([sys.executable,'-c',\"import socket; s=socket.socket(); s.bind(('127.0.0.1',0))\"],capture_output=True)\nprint(r.returncode != 0)\n")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "True")

    def test_socket_descriptor_is_closed(self):
        with socket.socket() as sock:
            fd = sock.fileno()
            with tempfile.NamedTemporaryFile("w", suffix=".py") as script:
                script.write(f"import os\ntry: os.fstat({fd}); print('BAD')\nexcept OSError: print('closed')\n")
                script.flush()
                p = subprocess.run([str(BIN), "--", "python3", script.name], pass_fds=(fd,), capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "closed")


if __name__ == "__main__":
    unittest.main()
