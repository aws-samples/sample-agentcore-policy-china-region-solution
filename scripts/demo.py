#!/usr/bin/env python3
"""Call both gateways with the same Auth0 token and compare Cedar decisions.

For each row in interceptor/policies/<scenario>/tests.json, send an MCP
tools/call to the China gateway (Lambda interceptor) and the global gateway
(Policy in AgentCore), then print a side-by-side table.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

import common
import switch_scenario


def expected(row, now):
    if row["expect"] == "TIME_09_17":  # same test as Cedar: 9h <= now.toTime() <= 17h
        seconds = now.hour * 3600 + now.minute * 60 + now.second
        return "ALLOW" if 9 * 3600 <= seconds <= 17 * 3600 else "DENY"
    return row["expect"]


def post(url, token, body, session_id=None):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            sid = resp.headers.get("Mcp-Session-Id")
    except urllib.error.HTTPError as e:
        return {"httpError": e.code, "text": e.read().decode()[:300]}, None
    if raw.lstrip().startswith("{"):
        return json.loads(raw), sid
    for line in raw.splitlines():  # text/event-stream
        if line.startswith("data:"):
            msg = json.loads(line[5:].strip())
            if "id" in msg:
                return msg, sid
    return {"text": raw[:300]}, sid


def classify(msg):
    if "httpError" in msg:
        return "ERROR", f"HTTP {msg['httpError']}: {msg['text']}"
    if "error" in msg:
        err = msg["error"] or {}
        if err.get("code") == -32002 and "Tool Execution Denied" in str(err.get("message")):
            return "DENY", err["message"]
        return "ERROR", json.dumps(err)[:200]
    result = msg.get("result") or {}
    text = " ".join(c.get("text", "") for c in result.get("content", []) if isinstance(c, dict))
    if result.get("isError") and "AuthorizeActionException" in text:
        return "DENY", text
    if result.get("isError"):
        return "ERROR", text[:200]
    return "ALLOW", text[:120]


class Gateway:
    def __init__(self, which, token):
        self.which = which
        self.url = common.stack_outputs(common.session(which), common.STACKS["gateway"])["GatewayUrl"]
        self.token = token
        self.session_id = None
        self.next_id = 1

    def initialize(self):
        msg, sid = post(self.url, self.token, {
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "cedar-demo", "version": "1.0"}},
        })
        if "result" not in msg:
            raise SystemExit(f"[{self.which}] initialize failed: {msg}")
        self.session_id = sid

    def list_tools(self):
        self.next_id += 1
        msg, _ = post(self.url, self.token, {"jsonrpc": "2.0", "id": self.next_id, "method": "tools/list"}, self.session_id)
        tools = (msg.get("result") or {}).get("tools")
        if tools is None:
            return None
        return sorted(t["name"].split("___", 1)[-1] for t in tools)

    def call(self, tool, arguments):
        self.next_id += 1
        msg, _ = post(self.url, self.token, {
            "jsonrpc": "2.0", "id": self.next_id, "method": "tools/call",
            "params": {"name": f"InsuranceAPI___{tool}", "arguments": arguments},
        }, self.session_id)
        return classify(msg)


def run_scenario(scenario, gateways, verbose):
    """Print the comparison table for one scenario; return True when everything matches."""
    which = [g.which for g in gateways]
    rows = json.load(open(os.path.join(common.POLICY_ROOT, scenario, "tests.json")))
    now = datetime.now(timezone.utc)
    print(f"\n=== {scenario}   (UTC {now:%H:%M})")
    header = f"{'tool':18} {'arguments':58} {'expected':8} " + " ".join(f"{w:8}" for w in which) + "  match"
    print(header)
    print("-" * len(header))
    failures = 0
    for row in rows:
        exp = expected(row, now)
        results = [g.call(row["tool"], row["arguments"]) for g in gateways]
        ok = all(r[0] == exp for r in results)
        failures += not ok
        args_text = json.dumps(row["arguments"], separators=(",", ":"))
        args_text = args_text if len(args_text) <= 58 else args_text[:55] + "..."
        print(f"{row['tool']:18} {args_text:58} {exp:8} " + " ".join(f"{r[0]:8}" for r in results)
              + f"  {'OK' if ok else 'MISMATCH'}")
        if verbose or not ok:
            for w, r in zip(which, results):
                print(f"    [{w}] {r[1]}")
    expected_list = json.load(open(os.path.join(common.POLICY_ROOT, scenario, "tools_list.json")))
    lists = {g.which: g.list_tools() for g in gateways}
    list_ok = all(v == expected_list for v in lists.values())
    print(f"tools/list  expected {expected_list}")
    for w, v in lists.items():
        print(f"            {w:8} {v}  {'OK' if v == expected_list else 'MISMATCH'}")
    print(f"result: {len(rows) - failures}/{len(rows)} calls match, tools/list {'matches' if list_ok else 'differs'}")
    return failures == 0 and list_ok


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("scenario", nargs="?", default="all", help="scenario folder name, or 'all' (default)")
    ap.add_argument("--region", choices=["cn", "global", "both"],
                    default="both" if common.global_enabled() else "cn")
    ap.add_argument("--no-switch", action="store_true", help="do not activate the scenario first")
    ap.add_argument("-v", "--verbose", action="store_true", help="print the response text for each call")
    args = ap.parse_args(argv)
    names = common.scenarios() if args.scenario == "all" else [args.scenario]
    for n in names:
        common.scenario_files(n)  # validate
    token = common.access_token()
    gateways = [Gateway(w, token) for w in (["cn", "global"] if args.region == "both" else [args.region])]
    for g in gateways:
        g.initialize()
    summary = []
    for name in names:
        if not args.no_switch:
            switch_scenario.main([name, "--region", args.region])
        summary.append((name, run_scenario(name, gateways, args.verbose)))
    print("\n=== summary")
    for name, ok in summary:
        print(f"  {name:22} {'OK' if ok else 'MISMATCH'}")
    return 0 if all(ok for _, ok in summary) else 1


if __name__ == "__main__":
    sys.exit(main())
