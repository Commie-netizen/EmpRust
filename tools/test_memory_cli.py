"""Offline smoke test and byte-budget measurement; synthetic conversations only."""
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        prefix = [binary, "memory", "--database", str(root / "memory.sqlite")]

        def run(*args):
            return json.loads(subprocess.check_output(prefix + list(args), timeout=30))

        conversations = [{"provider": "synthetic", "id": str(i), "title": f"Test {i}",
                          "messages": [{"id": "one", "role": "user", "text":
                                        f"Decision {i}: Rust architecture SQLite local memory. " * 100}]}
                         for i in range(100)]
        fixture = root / "fixture.json"
        fixture.write_text(json.dumps(conversations), encoding="utf-8")
        run("import", str(fixture))
        assert run("import", str(fixture))["new_chunks"] == 0
        search = run("search", "Rust architecture", "--budget", "4000")
        assert search["hits"]
        hit = run("get", search["hits"][0]["id"])
        assert "Rust" in hit["text"]
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "memory_search", "arguments": {"query": "Rust", "budget": 2000}}},
        ]
        output = subprocess.check_output(prefix + ["mcp"], input="".join(json.dumps(r) + "\n" for r in requests).encode(), timeout=30)
        replies = [json.loads(line) for line in output.splitlines()]
        assert [r["id"] for r in replies] == [1, 2, 3]
        assert len(replies[1]["result"]["tools"]) == 3
        assert replies[2]["result"]["isError"] is False
        received = []

        class LocalModel(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                received.append(body)
                data = json.dumps({"choices": [{"message": {"content": "Synthetic local answer"}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        server = HTTPServer(("127.0.0.1", 0), LocalModel)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            result = run("ask", "Rust architecture", "--model", "synthetic",
                         "--endpoint", f"http://127.0.0.1:{server.server_port}/v1/chat/completions")
            assert result["answer"] == "Synthetic local answer"
            assert received[0]["max_tokens"] == 512
            config = root / "plan.json"
            config.write_text(json.dumps({"endpoint": f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                                         "model": "synthetic", "question": "Explain Rust",
                                         "chunks": [search["hits"][0]["id"]]}), encoding="utf-8")
            plan = run("prepare", str(config))
            assert plan["state"] == "prepared"
            assert len(received) == 1  # Preparing is offline.
            done = run("execute", plan["id"], "--approve", plan["approval_digest"])
            assert done["state"] == "completed"
            assert len(received) == 2
            second = subprocess.run(prefix + ["execute", plan["id"], "--approve", plan["approval_digest"]], capture_output=True, timeout=30)
            assert second.returncode != 0 and len(received) == 2
            run("feedback", plan["id"], "--rating", "-1", "--note", "too_verbose")
            adaptation = run("adapt")
            assert adaptation["candidate"]["output_tokens"] == 256
            assert adaptation["applied"] is False
            assert run("profile")["preferences"]["output_tokens"] == 512
            profile_file = root / "profile.json"
            profile_file.write_text(json.dumps(adaptation["candidate"]), encoding="utf-8")
            assert run("set-profile", str(profile_file), "--reason", "user accepted shorter output")["preferences"]["output_tokens"] == 256
            assert run("restore-profile", "1")["preferences"]["output_tokens"] == 512
            exported = run("export")
            assert len(exported) == 100
            run("forget", "synthetic", "0", "--confirm")
            assert len(run("export")) == 99
            encrypted = root / "encrypted.sqlite"
            environment = dict(os.environ, EMPREINTE_TEST_KEY="synthetic-only-test-passphrase")
            subprocess.check_output(prefix + ["encrypt-copy", str(encrypted), "--new-key-env", "EMPREINTE_TEST_KEY"], env=environment, timeout=30)
            encrypted_prefix = [binary, "memory", "--database", str(encrypted), "--database-key-env", "EMPREINTE_TEST_KEY"]
            stats = json.loads(subprocess.check_output(encrypted_prefix + ["stats"], env=environment, timeout=30))
            assert stats["storage"] == "SQLCipher encrypted" and stats["conversations"] == 99
            assert run("recover")["retried"] == 0
        finally:
            server.shutdown()
            server.server_close()
            worker.join()
        source_bytes = sum(len(m["text"].encode()) for c in conversations for m in c["messages"])
        result_bytes = len(json.dumps(search, ensure_ascii=False, separators=(",", ":")).encode())
        assert result_bytes <= 4000
        print(json.dumps({"ok": True, "conversations": 100, "source_text_bytes": source_bytes,
                          "search_json_bytes": result_bytes,
                          "byte_reduction_percent": round(100 * (1 - result_bytes / source_bytes), 2),
                          "note": "Synthetic byte-volume comparison, not token count or retrieval-quality benchmark."}))


if __name__ == "__main__":
    main()
