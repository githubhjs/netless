import os
import pathlib
import socket
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = ROOT / "build" / "netless"


class NetlessTests(unittest.TestCase):
    def run_child(self, source, *args, pass_fds=()):
        with tempfile.NamedTemporaryFile("w", suffix=".py") as script:
            script.write(source)
            script.flush()
            return subprocess.run([str(BIN), *args, "--", "python3", script.name],
                                  capture_output=True, text=True, pass_fds=pass_fds)

    def test_dns_and_ip_socket_creation_are_denied(self):
        p = self.run_child("import socket\ntry: socket.socket()\nexcept OSError as e: print(e.errno)\ntry: socket.getaddrinfo('example.com', 80)\nexcept OSError: print('dns denied')\n")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.splitlines(), ["1", "dns denied"])  # EPERM; resolver cannot open a socket

    def test_bind_and_raw_socket_are_denied(self):
        code = "import socket, errno\nfor family, kind in [(socket.AF_INET,socket.SOCK_STREAM),(socket.AF_INET6,socket.SOCK_DGRAM),(socket.AF_PACKET,socket.SOCK_RAW)]:\n try: socket.socket(family,kind); print('BAD')\n except OSError as e: print(e.errno)\n"
        p = self.run_child(code)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.splitlines(), ["1", "1", "1"])

    def test_filter_is_inherited_by_fork_and_exec(self):
        code = "import os, subprocess, sys\nif os.fork()==0: os.execv(sys.executable,[sys.executable,'-c',\"import socket; socket.socket()\"])\n_, status=os.wait()\nprint(os.waitstatus_to_exitcode(status))\n"
        p = self.run_child(code)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "1")

    def test_inherited_socket_fd_is_rejected(self):
        with socket.socket() as sock:
            fd = sock.fileno()
            p = self.run_child(f"import os\ntry: os.fstat({fd}); print('BAD')\nexcept OSError: print('closed')\n", pass_fds=(fd,))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "closed")

    def test_additional_syscall_denial_and_invalid_configuration(self):
        p = subprocess.run([str(BIN), "--deny-syscall", "ptrace", "--", "true"], capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        bad = subprocess.run([str(BIN), "--deny-syscall", "not_a_syscall", "--", "true"], capture_output=True)
        self.assertEqual(bad.returncode, 2)


if __name__ == "__main__":
    unittest.main()
