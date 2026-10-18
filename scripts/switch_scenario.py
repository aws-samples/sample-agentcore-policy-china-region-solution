#!/usr/bin/env python3
"""Activate a Cedar scenario in one or both regions.

global: replace every policy in the Policy in AgentCore engine with the scenario's .cedar files.
cn:     point the interceptor Lambda at the scenario folder (POLICY_SCENARIO env var).
"""
import argparse
import os
import sys
import time

from botocore.exceptions import ClientError

import common


TRANSITIONAL = {"CREATING", "UPDATING", "DELETING"}


def wait_policy(client, engine_id, policy_id, want, timeout=180, not_found_grace=30):
    """Poll a policy until it reaches `want`, a terminal *_FAILED state, or disappears.

    Returns the policy dict, {"status": "SETTLED"...} when want == "SETTLED" and the
    policy left every transitional state, or None once it no longer exists. GetPolicy
    can briefly return NotFound right after CreatePolicy, so NotFound is retried for
    `not_found_grace` seconds unless we are waiting for deletion.
    """
    start = time.time()
    while time.time() - start < timeout:
        try:
            p = client.get_policy(policyEngineId=engine_id, policyId=policy_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            if want == "DELETED" or time.time() - start > not_found_grace:
                return None
            time.sleep(3)
            continue
        status = p.get("status")
        if status == want or (status and status.endswith("FAILED")):
            return p
        if want == "SETTLED" and status not in TRANSITIONAL:
            return p
        time.sleep(3)
    raise SystemExit(f"timed out waiting for policy {policy_id} to become {want}")


def delete_policy(client, engine_id, policy_id):
    """Delete once the policy is out of any transitional state; tolerate it already being gone."""
    if wait_policy(client, engine_id, policy_id, "SETTLED", not_found_grace=0) is None:
        return
    try:
        client.delete_policy(policyEngineId=engine_id, policyId=policy_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    wait_policy(client, engine_id, policy_id, "DELETED")


FINDING_PREFIXES = ("Overly Permissive:", "Overly Restrictive:")


def is_findings_only(reasons):
    """True when every failure reason is an analyzer finding, not a syntax or type error."""
    return bool(reasons) and all(str(r).startswith(FINDING_PREFIXES) for r in reasons)


def create(client, engine_id, name, statement, description):
    """Create with FAIL_ON_ANY_FINDINGS; fall back to IGNORE_ALL_FINDINGS only for analysis findings.

    Demo policies are deliberately broad (an unconditional permit or forbid), which the
    policy analyzer reports as Overly Permissive / Overly Restrictive. Any other failure
    (syntax, schema, type errors) is fatal.
    """
    for mode in ("FAIL_ON_ANY_FINDINGS", "IGNORE_ALL_FINDINGS"):
        created = client.create_policy(
            policyEngineId=engine_id, name=name, definition={"cedar": {"statement": statement}},
            validationMode=mode, description=description,
        )
        p = wait_policy(client, engine_id, created["policyId"], "ACTIVE")
        if p.get("status") == "ACTIVE":
            return mode
        reasons = p.get("statusReasons") or []
        delete_policy(client, engine_id, created["policyId"])
        if mode == "IGNORE_ALL_FINDINGS" or not is_findings_only(reasons):
            raise SystemExit(f"policy {name} {p.get('status')} ({mode}): {reasons}")
        for r in reasons:
            print(f"[global] finding on {name}: {r.split(':', 1)[0]}")
    raise AssertionError("unreachable")


def clear_global():
    """Delete every policy in the global engine (policies live outside CloudFormation)."""
    sess = common.session("global")
    engine_id = common.stack_outputs(sess, common.STACKS["engine"])["PolicyEngineId"]
    client = sess.client("bedrock-agentcore-control")
    existing = []
    for page in client.get_paginator("list_policies").paginate(policyEngineId=engine_id):
        existing += page.get("policies", [])
    for p in existing:
        delete_policy(client, engine_id, p["policyId"])
    print(f"[global] removed {len(existing)} policies")


def switch_global(scenario):
    sess = common.session("global")
    engine_id = common.stack_outputs(sess, common.STACKS["engine"])["PolicyEngineId"]
    gateway_arn = common.stack_outputs(sess, common.STACKS["gateway"])["GatewayArn"]
    principal_sub = common.stack_parameter(sess, common.STACKS["gateway"], "DemoPrincipalSub")
    client = sess.client("bedrock-agentcore-control")
    existing = []
    for page in client.get_paginator("list_policies").paginate(policyEngineId=engine_id):
        existing += page.get("policies", [])
    for p in existing:
        delete_policy(client, engine_id, p["policyId"])
    print(f"[global] removed {len(existing)} policies")
    prefix = "s" + scenario.split("-", 1)[0]
    for path in common.scenario_files(scenario):
        stem = os.path.basename(path)[: -len(".cedar")]
        name = f"{prefix}_{stem.replace('-', '_')}"[:48]
        statement = common.render_policy(open(path).read(), gateway_arn, principal_sub)
        mode = create(client, engine_id, name, statement, f"{scenario}/{stem}")
        print(f"[global] ACTIVE {name} ({mode})")


def switch_cn(scenario):
    sess = common.session("cn")
    fn = common.stack_outputs(sess, common.STACKS["gateway"])["InterceptorFunctionName"]
    lam = sess.client("lambda")
    env = lam.get_function_configuration(FunctionName=fn)["Environment"]["Variables"]
    env["POLICY_SCENARIO"] = scenario
    lam.update_function_configuration(FunctionName=fn, Environment={"Variables": env})
    lam.get_waiter("function_updated_v2").wait(FunctionName=fn)
    print(f"[cn] {fn} POLICY_SCENARIO={scenario}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("scenario", nargs="?")
    ap.add_argument("--clear-global", action="store_true", help="only delete all policies in the global engine")
    ap.add_argument("--region", choices=["cn", "global", "both"],
                    default="both" if common.global_enabled() else "cn")
    args = ap.parse_args(argv)
    if args.clear_global:
        clear_global()
        return 0
    if not args.scenario:
        ap.error("scenario is required")
    common.scenario_files(args.scenario)  # validate name early
    if args.region in ("global", "both"):
        switch_global(args.scenario)
    if args.region in ("cn", "both"):
        switch_cn(args.scenario)


if __name__ == "__main__":
    sys.exit(main())
