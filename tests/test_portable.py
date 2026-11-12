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

    def test_network_socket_families_are_blocked(self):
        families = ["AF_INET", "AF_INET6", "AF_UNIX"]
        code = "import socket\nfor name in " + repr(families) + ":\n try: socket.socket(getattr(socket,name)); print('BAD')\n except OSError: print('blocked')\n"
        p = self.run_child(code)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.splitlines(), ["blocked"] * len(families))

    def test_dns_lookup_cannot_open_network_socket(self):
        p = self.run_child("import socket\ntry: socket.getaddrinfo('example.com',80); print('BAD')\nexcept OSError: print('blocked')\n")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "blocked")

    def test_restriction_is_inherited_by_exec_child(self):
        p = self.run_child("import subprocess,sys\nr=subprocess.run([sys.executable,'-c','import socket; socket.socket()'],capture_output=True)\nprint(r.returncode != 0)\n")
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
