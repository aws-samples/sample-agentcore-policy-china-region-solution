"""The gateway target's inline tool schema must match interceptor/tool_schema.json."""
import json
import os

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CfnLoader(yaml.SafeLoader):
    pass


def _tag(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {suffix: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {suffix: loader.construct_sequence(node, deep=True)}
    return {suffix: loader.construct_mapping(node, deep=True)}


CfnLoader.add_multi_constructor("!", _tag)


def to_mcp(schema):
    out = {}
    for k, v in schema.items():
        key = k[0].lower() + k[1:]
        if k == "Properties":
            out[key] = {name: to_mcp(p) for name, p in v.items()}
        elif isinstance(v, dict):
            out[key] = to_mcp(v)
        else:
            out[key] = v
    return out


def test_inline_payload_matches_tool_schema():
    tpl = yaml.load(open(os.path.join(ROOT, "infra", "template.yaml")), Loader=CfnLoader)
    payload = tpl["Resources"]["GatewayTarget"]["Properties"]["TargetConfiguration"]["Mcp"]["Lambda"]["ToolSchema"]["InlinePayload"]
    from_template = [
        {"name": t["Name"], "description": t["Description"], "inputSchema": to_mcp(t["InputSchema"])} for t in payload
    ]
    bundled = json.load(open(os.path.join(ROOT, "interceptor", "tool_schema.json")))
    assert from_template == bundled
