"""Exercise the documented entry points in separate processes with fresh identities."""

import os
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path


class CommandLineTests(unittest.TestCase):
    def test_init_server_and_client(self):
        with tempfile.TemporaryDirectory() as temp:
            env = {k: v for k, v in os.environ.items() if not k.startswith("SC_")}
            env.update(
                SC_PKI_DIR=str(Path(temp) / "pki"),
                SC_CA_KEY_PASSWORD="one-use test password",
            )
            command = [sys.executable, "-B", "-m", "sovereign_chain"]
            subprocess.run(
                command + ["init-pki"],
                env=env,
                check=True,
                capture_output=True,
                timeout=20,
            )
            env.pop("SC_CA_KEY_PASSWORD")
            with subprocess.Popen(
                command + ["server", "--listen-port", "0"],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            ) as server:
                try:
                    lines = queue.Queue()
                    reader = threading.Thread(
                        target=lambda: lines.put(server.stderr.readline()), daemon=True
                    )
                    reader.start()
                    first = lines.get(timeout=10)
                    self.assertIn("Listening on 127.0.0.1:", first)
                    reader.join(3)
                    env["SC_SERVER_PORT"] = first.strip().rsplit(":", 1)[1]
                    result = subprocess.run(
                        command + ["client", "--message", "hello"],
                        env=env,
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=10,
                    )
                    self.assertEqual(result.stdout.strip(), "echo: hello")
                finally:
                    server.terminate()
                    server.wait(timeout=5)
