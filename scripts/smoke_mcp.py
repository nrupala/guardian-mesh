#!/usr/bin/env python3
# Copyright (c) 2026 Nrupal Akolkar
# SPDX-License-Identifier: Apache-2.0

"""GMSI-124 MCP smoke driver for the guardian-mesh gm-mcp stdio server.

This is test scaffolding, not shipped runtime. It spawns gm-mcp, speaks the
newline-delimited JSON-RPC MCP stdio transport, and asserts on parsed fields.

Usage:
  scripts/smoke_mcp.py --gm-mcp PATH [--endpoint URL]
  scripts/smoke_mcp.py --gm-mcp PATH --endpoint URL --unreachable

Prints PASS/FAIL per leg and exits non-zero on any failure. --quiet suppresses
the per-leg PASS lines (errors still go to stderr) so scripts/smoke.sh can print
one summary line per leg.
"""

import argparse
import json
import os
import queue
import subprocess
import sys
import threading

DEFAULT_ENDPOINT = "http://127.0.0.1:50051"
UNREACHABLE_ENDPOINT = "http://127.0.0.1:59999"
SUPPORTED_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18"}
TOOL_NAMES = {
    "guardian_audit",
    "guardian_evaluate",
    "guardian_health",
    "guardian_verify",
}
PROOF_FIELDS = {
    "payload",
    "payload_type",
    "crc32c",
    "ml_dsa_65_signature",
    "timestamp",
    "nonce",
}


class McpProcess:
    def __init__(self, command, endpoint, timeout=30):
        env = os.environ.copy()
        env["GM_ENDPOINT"] = endpoint
        self.timeout = timeout
        self.next_id = 1
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=env,
        )
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self._read_stdout, daemon=True)
        self.reader.start()

    def _read_stdout(self):
        try:
            for line in self.proc.stdout:
                self.lines.put(line)
        finally:
            self.lines.put(None)

    def send(self, message):
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()

    def notify(self, method, params=None):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)

    def request(self, method, params=None):
        request_id = self.next_id
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)
        return self._read_response(request_id)

    def _read_response(self, request_id):
        while True:
            try:
                line = self.lines.get(timeout=self.timeout)
            except queue.Empty:
                raise RuntimeError("timeout waiting for response id %d" % request_id)
            if line is None:
                raise RuntimeError("gm-mcp closed stdout")
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError as error:
                raise RuntimeError("non-JSON stdout line %r: %s" % (line, error))
            if message.get("id") != request_id:
                raise RuntimeError(
                    "unexpected response for id %r: %r" % (request_id, message)
                )
            return message

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=10)


def result_of(response, method):
    if "error" in response:
        raise RuntimeError("%s returned JSON-RPC error: %r" % (method, response["error"]))
    if "result" not in response:
        raise RuntimeError("%s response has no result: %r" % (method, response))
    return response["result"]


def tool_payload(tool_result, tool_name):
    if not isinstance(tool_result, dict):
        raise RuntimeError("%s result is not an object" % tool_name)
    content = tool_result.get("content")
    if not isinstance(content, list) or not content:
        raise RuntimeError("%s result has no content" % tool_name)
    first = content[0]
    if not isinstance(first, dict) or first.get("type") != "text":
        raise RuntimeError("%s first content item is not text" % tool_name)
    text = first.get("text")
    if not isinstance(text, str):
        raise RuntimeError("%s text content is not a string" % tool_name)
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise RuntimeError("%s text is not JSON: %s" % (tool_name, error))


def is_tool_error(tool_result):
    return bool(isinstance(tool_result, dict) and tool_result.get("isError"))


class Legs:
    def __init__(self, quiet):
        self.quiet = quiet
        self.failed = 0

    def run(self, name, fn):
        try:
            fn()
        except Exception as error:
            self.failed += 1
            print("FAIL %s: %s" % (name, error), file=sys.stderr)
            if not self.quiet:
                print("FAIL %s" % name)
            return False
        if not self.quiet:
            print("PASS %s" % name)
        return True


def check_initialize(client):
    result = result_of(
        client.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "guardian-mesh-smoke", "version": "0"},
            },
        ),
        "initialize",
    )
    version = result.get("protocolVersion")
    if version not in SUPPORTED_VERSIONS:
        raise RuntimeError("unexpected protocolVersion %r" % (version,))
    capabilities = result.get("capabilities")
    if not isinstance(capabilities, dict) or not isinstance(capabilities.get("tools"), dict):
        raise RuntimeError("initialize result has no tools capability: %r" % (capabilities,))
    server_info = result.get("serverInfo")
    if not isinstance(server_info, dict) or server_info.get("name") != "guardian-mesh":
        raise RuntimeError("unexpected serverInfo %r" % (server_info,))
    if not isinstance(server_info.get("version"), str):
        raise RuntimeError("serverInfo.version is not a string")


def check_tools_list(client):
    result = result_of(client.request("tools/list"), "tools/list")
    tools = result.get("tools")
    if not isinstance(tools, list):
        raise RuntimeError("tools/list result has no tools array")
    names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
    if names != TOOL_NAMES:
        raise RuntimeError("tool names %r != %r" % (sorted(names), sorted(TOOL_NAMES)))
    for tool in tools:
        schema = tool.get("inputSchema")
        if not isinstance(schema, dict) or schema.get("type") != "object":
            raise RuntimeError("tool %r has no object inputSchema" % (tool.get("name"),))
        if not isinstance(schema.get("properties"), dict):
            raise RuntimeError("tool %r has no properties" % (tool.get("name"),))
        if not isinstance(schema.get("required"), list):
            raise RuntimeError("tool %r has no required list" % (tool.get("name"),))


def check_health(client):
    tool_result = result_of(
        client.request("tools/call", {"name": "guardian_health", "arguments": {}}),
        "guardian_health",
    )
    if is_tool_error(tool_result):
        raise RuntimeError("guardian_health returned isError: %r" % (tool_result,))
    payload = tool_payload(tool_result, "guardian_health")
    if payload.get("status") not in {"SERVING", "DEGRADED"}:
        raise RuntimeError("unexpected health status %r" % (payload.get("status"),))
    if "build_version" not in payload or "node_id" not in payload:
        raise RuntimeError("health payload is missing build_version or node_id")


def check_evaluate(client, state):
    tool_result = result_of(
        client.request(
            "tools/call",
            {
                "name": "guardian_evaluate",
                "arguments": {
                    "action_type": "TOOL_CALL",
                    "context": "smoke",
                    "target": "mcp",
                },
            },
        ),
        "guardian_evaluate",
    )
    if is_tool_error(tool_result):
        raise RuntimeError("guardian_evaluate returned isError: %r" % (tool_result,))
    payload = tool_payload(tool_result, "guardian_evaluate")
    if payload.get("verdict") != "ALLOW":
        raise RuntimeError("unexpected verdict %r" % (payload.get("verdict"),))
    proof_envelope = payload.get("proof_envelope")
    if not isinstance(proof_envelope, dict):
        raise RuntimeError("evaluate result has no proof_envelope object")
    missing = PROOF_FIELDS - set(proof_envelope)
    if missing:
        raise RuntimeError("proof_envelope is missing fields %r" % (sorted(missing),))
    for field in PROOF_FIELDS:
        if not isinstance(proof_envelope.get(field), str):
            raise RuntimeError("proof_envelope.%s is not a string" % field)
    state["proof_envelope"] = proof_envelope


def check_verify(client, state):
    proof_envelope = state.get("proof_envelope")
    if not isinstance(proof_envelope, dict):
        raise RuntimeError("no proof_envelope captured from evaluate")
    tool_result = result_of(
        client.request(
            "tools/call",
            {"name": "guardian_verify", "arguments": {"proof": proof_envelope}},
        ),
        "guardian_verify",
    )
    if is_tool_error(tool_result):
        raise RuntimeError("guardian_verify returned isError: %r" % (tool_result,))
    payload = tool_payload(tool_result, "guardian_verify")
    if payload.get("valid") is not True:
        raise RuntimeError("guardian_verify did not report valid=true: %r" % (payload,))


def check_audit(client):
    tool_result = result_of(
        client.request("tools/call", {"name": "guardian_audit", "arguments": {}}),
        "guardian_audit",
    )
    if is_tool_error(tool_result):
        raise RuntimeError("guardian_audit returned isError: %r" % (tool_result,))
    payload = tool_payload(tool_result, "guardian_audit")
    if not isinstance(payload.get("entries"), list):
        raise RuntimeError("audit result has no entries array")
    if not isinstance(payload.get("verification"), dict):
        raise RuntimeError("audit result has no verification object")


def check_unreachable_evaluate(client):
    tool_result = result_of(
        client.request(
            "tools/call",
            {
                "name": "guardian_evaluate",
                "arguments": {
                    "action_type": "TOOL_CALL",
                    "context": "smoke",
                    "target": "mcp-unreachable",
                },
            },
        ),
        "guardian_evaluate",
    )
    if tool_result.get("isError") is not True:
        raise RuntimeError("unreachable evaluate did not return isError=true: %r" % (tool_result,))
    payload = tool_payload(tool_result, "guardian_evaluate")
    text = json.dumps(payload)
    if "NO verdict was issued" not in text or "BLOCK" not in text:
        raise RuntimeError("unreachable evaluate text is not fail-closed: %r" % (payload,))


def check_ping(client):
    result = result_of(client.request("ping"), "ping")
    if result != {}:
        raise RuntimeError("unexpected ping result %r" % (result,))


def run_live(client, legs):
    legs.run("mcp initialize", lambda: check_initialize(client))
    client.notify("notifications/initialized")
    legs.run("mcp tools/list", lambda: check_tools_list(client))
    legs.run("mcp guardian_health", lambda: check_health(client))
    state = {}
    legs.run("mcp guardian_evaluate", lambda: check_evaluate(client, state))
    legs.run("mcp guardian_verify", lambda: check_verify(client, state))
    legs.run("mcp guardian_audit", lambda: check_audit(client))


def run_unreachable(client, legs):
    legs.run("mcp initialize (unreachable endpoint)", lambda: check_initialize(client))
    client.notify("notifications/initialized")
    legs.run("mcp tools/list (unreachable endpoint)", lambda: check_tools_list(client))
    legs.run("mcp evaluate is fail-closed", lambda: check_unreachable_evaluate(client))
    legs.run("mcp ping still answers", lambda: check_ping(client))


def main():
    parser = argparse.ArgumentParser(description="Guardian Mesh gm-mcp smoke driver")
    parser.add_argument("--gm-mcp", required=True, help="path to the gm-mcp binary")
    parser.add_argument("--endpoint", help="daemon gRPC endpoint")
    parser.add_argument(
        "--unreachable",
        action="store_true",
        help="assert fail-closed behaviour against an unreachable endpoint",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress per-leg PASS lines (errors still go to stderr)",
    )
    args = parser.parse_args()

    endpoint = args.endpoint
    if not endpoint:
        endpoint = UNREACHABLE_ENDPOINT if args.unreachable else DEFAULT_ENDPOINT

    legs = Legs(args.quiet)
    try:
        client = McpProcess([args.gm_mcp], endpoint)
    except Exception as error:
        print("FAIL mcp spawn: %s" % (error,), file=sys.stderr)
        return 1

    try:
        if args.unreachable:
            run_unreachable(client, legs)
        else:
            run_live(client, legs)
    finally:
        client.close()

    return 0 if legs.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
