# 中国区 AgentCore Gateway：用 Lambda Interceptor 实现 Cedar 策略管控

亚马逊云科技中国区域（北京 cn-north-1、宁夏 cn-northwest-1）已提供 Amazon Bedrock AgentCore Gateway，
但暂未提供 **Policy in AgentCore**。本示例用 Gateway 的 **Lambda Interceptor** 补上这块能力：
Interceptor 内置 [Cedar](https://www.cedarpolicy.com/) 引擎（[cedarpy](https://github.com/k9securityio/cedar-py)，
即 Rust 版 Cedar 的 Python 绑定），按与 Policy in AgentCore **相同的 Cedar 策略原文**放行或拦截工具调用。

一条命令部署，一条命令演示 5 类典型策略。可选同时在海外区域部署一套使用真正 Policy in AgentCore 的对照组，
逐条对比两边的判定结果。

```
                       OAuth 2.0 / OIDC 身份提供方（默认 Auth0，client_credentials）
                       /                                              \
  中国区 AgentCore Gateway（CUSTOM_JWT）                 海外 AgentCore Gateway（CUSTOM_JWT，可选对照组）
    │ Lambda Interceptor（REQUEST + RESPONSE）             │ Policy in AgentCore 策略引擎（ENFORCE）
    │ cedarpy + interceptor/policies/<场景>/*.cedar        │ 同一批 .cedar 文件，经 CreatePolicy 加载
    ▼                                                      ▼
  Lambda 目标 "InsuranceAPI"（5 个模拟理赔工具）          Lambda 目标 "InsuranceAPI"
```

## 实测效果

2026-10-18 在 cn-north-1（Interceptor）与 us-west-2（Policy in AgentCore）上，用同一个 token 对 5 个场景逐条对比：

| 对比项 | 结果 |
|---|---|
| 工具调用 `tools/call` 的放行或拦截 | 20 / 20 一致 |
| 工具列表 `tools/list` 中可见的工具 | 5 / 5 个场景一致 |
| 拦截时返回的错误 | 结构与文本一致（forbid 命中时策略名的写法不同，见下文） |

被拦截的调用不会到达后端工具，客户端收到与 Policy in AgentCore 相同的 JSON-RPC 错误：

```json
{"jsonrpc": "2.0", "id": 3, "error": {"code": -32002,
 "message": "Tool Execution Denied: Tool call not allowed due to policy enforcement [No policy applies to the request (denied by default).]"}}
```

## 前置条件

1. **一个中国区账号**，以及本机已配置好的 AWS CLI profile（`aws configure --profile <名称>`）。
   部署身份需要 CloudFormation、IAM、Lambda、S3、KMS、Secrets Manager 和 Bedrock AgentCore 的创建权限。
2. **本机工具**：AWS CLI v2、Python 3.9 及以上（含 pip 与 venv）、bash。不需要 SAM CLI，也不需要 Docker。
   如果访问 PyPI 较慢，请先设置国内镜像，例如 `export PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/`。
3. **一个 OAuth 2.0 / OIDC 身份提供方**，能用 client_credentials 方式签发 JWT 访问令牌。
   中国区没有 Amazon Cognito 用户池，因此 Gateway 的 JWT 认证需要外部身份提供方。
   示例默认使用 Auth0，按下面的步骤准备即可。也可以换成你自己的 OAuth 服务。

### 准备 Auth0（默认）

1. 注册或登录 [Auth0](https://auth0.com/)，记下租户域名，例如 `your-tenant.us.auth0.com`。
2. 在 **Applications > APIs** 中创建一个 API：
   - **Identifier** 填 `https://agentcore-cedar-demo`（任意 URI 均可，它就是 audience）。
   - 签名算法保持 **RS256**。
   - 在 **Permissions** 页添加权限 `invoke:agentcore`。
3. 在 **Applications > Applications** 中创建 **Machine to Machine** 类型的应用，
   授权它访问上一步的 API，并勾选 `invoke:agentcore`。
4. 记下该应用的 **Client ID** 和 **Client Secret**。

Gateway 会通过公网读取身份提供方的 OIDC discovery 和 JWKS，运行演示的机器也需要访问其 token 端点。

### 使用自己的 OAuth 服务

任何满足以下条件的身份提供方都可以替换 Auth0，只需修改 `config.env` 中的 `OIDC_*` 配置：

- 提供 OIDC discovery 地址（`.../.well-known/openid-configuration`），其中包含 `token_endpoint` 和 `jwks_uri`。
- 支持 client_credentials 授权，签发 RS256 签名的 JWT 访问令牌。
- 令牌包含 `sub`，`aud` 等于 `OIDC_AUDIENCE`，`scope` 声明中包含 `OIDC_SCOPE`。

场景 05 中有一条策略检查 Auth0 特有的 `gty` 声明。换用其他身份提供方时，请按实际令牌内容调整该场景，
详见[自定义策略](#自定义策略)。

## 快速开始

```bash
git clone https://github.com/aws-samples/sample-agentcore-policy-china-region-solution.git
cd sample-agentcore-policy-china-region-solution
cp config.env.example config.env
vi config.env                      # 填写 CN_PROFILE、OIDC_DISCOVERY_URL、OIDC_AUDIENCE、OIDC_CLIENT_ID

scripts/deploy.sh                  # 首次运行会提示输入 Client Secret（输入内容不回显）
scripts/demo.sh                    # 依次激活并演示全部 5 个场景
```

`deploy.sh` 依次完成以下工作。实测同时部署中国区和海外对照组约 7 分钟，只部署中国区会更快：

1. 检查 profile 是否为中国区身份，并向身份提供方申请一次测试令牌，确认配置无误。
   令牌中的 `sub` 会作为演示主体，供场景 05 使用。
2. 按 Lambda 的 arm64 / Python 3.12 平台下载 cedarpy，打包 Interceptor。
3. 创建私有 S3 桶存放部署包，并部署 Gateway 堆栈。
   Client Secret 作为 NoEcho 参数写入本堆栈的 Secrets Manager（使用专用 KMS 密钥加密），不会落盘或打印。
4. 首次部署会自动再执行一次，把新 Gateway 的 ARN 传给 Interceptor，作为 Cedar 的 resource。

`demo.sh` 的常用参数：

```bash
scripts/demo.sh                          # 全部场景
scripts/demo.sh 03-input-condition -v    # 单个场景，并打印每次调用的响应
scripts/demo.sh --region both            # 同时对比海外对照组（需先启用，见下文）
```

输出示例（启用了海外对照组，`global` 列是 Policy in AgentCore 的判定）：

```
=== 02-forbid-sensitive   (UTC 09:56)
tool               arguments                                                  expected cn       global    match
---------------------------------------------------------------------------------------------------------------
get_claim_status   {"claimId":"C-1001"}                                       ALLOW    ALLOW    ALLOW     OK
approve_claim      {"claimId":"C-1001","approved":true,"approvedAmountCent... ALLOW    ALLOW    ALLOW     OK
delete_claim       {"claimId":"C-1001"}                                       DENY     DENY     DENY      OK
tools/list  expected ['approve_claim', 'disburse_payment', 'file_claim', 'get_claim_status']
            cn       ['approve_claim', 'disburse_payment', 'file_claim', 'get_claim_status']  OK
            global   ['approve_claim', 'disburse_payment', 'file_claim', 'get_claim_status']  OK
result: 3/3 calls match, tools/list matches
```

## 演示场景

所有策略位于 `interceptor/policies/<场景>/`，每个 `.cedar` 文件一条策略。
同目录的 `tests.json` 是期望的判定结果，`tools_list.json` 是期望在 `tools/list` 中看到的工具。

| 场景 | 策略类型 | 演示内容 |
|---|---|---|
| `01-allowlist` | 工具白名单 | 只允许只读的 `get_claim_status`，其余工具默认拒绝。 |
| `02-forbid-sensitive` | 全部放行 + forbid | forbid 优先于 permit，`delete_claim` 被禁止。 |
| `03-input-condition` | 参数条件 | `amount`（JSON number，即 Cedar `decimal`）不超过 1000 且 `claimType` 属于指定集合；`approvedAmountCents`（integer，即 Cedar `Long`）小于 100000。 |
| `04-time-based` | 时间条件 | `disburse_payment` 仅在 UTC 09:00 至 17:00（北京时间 17:00 至次日 01:00）可用；另有一个有效、一个已过期的绝对日期窗口。 |
| `05-principal` | 调用者身份 | 按 `principal is OAuthUser`、特定 `sub`、`scope`（`like` 匹配）、缺失的 `role` 声明判定；并用 forbid 禁止 client_credentials 令牌付款。 |

场景 04 中 `disburse_payment` 的期望结果取决于运行时的 UTC 时间，演示脚本会自动计算。

## 工作原理

### 一个 Lambda，两个拦截点

Interceptor 是一个 Lambda 函数，在 Gateway 上同时注册为 REQUEST 和 RESPONSE 两种拦截器。

- **REQUEST 阶段拦截 `tools/call`。** 判定为拒绝时直接返回上面的 JSON-RPC 错误，请求不会到达后端工具。
- **RESPONSE 阶段过滤 `tools/list`。** 隐藏当前调用者肯定无权调用的工具，与 Policy in AgentCore 的行为一致。
  做法是在“工具参数未知”的前提下对每个工具做 Cedar 部分求值，结果已确定为拒绝的才隐藏。
  因此只在某些参数下才放行的工具仍会显示，例如场景 03 的 `file_claim`。
- **其他 MCP 方法原样放行**，例如 `initialize`、`ping` 和通知类消息。
- **任何内部错误都按拒绝处理**（fail closed），绝不会因为 Interceptor 出错而放行。

Cedar 策略不写进代码。`.cedar` 文件原文打包进 Lambda 部署包，与海外 Policy in AgentCore 使用的文本完全相同，
加载时只把 `{{GATEWAY_ARN}}`、`{{PRINCIPAL_SUB}}` 两个占位符替换为本区域的实际值。

### 请求如何映射为 Cedar 请求

映射方式与 Policy in AgentCore 一致，所以同一份 Cedar 策略在两边含义相同。

| Cedar 元素 | 来源 |
|---|---|
| principal | `AgentCore::OAuthUser::"<令牌的 sub>"`，令牌中的每个声明都成为字符串类型的 tag |
| action | `AgentCore::Action::"<目标名>___<工具名>"`，取自 `params.name` |
| resource | `AgentCore::Gateway::"<Gateway ARN>"` |
| `context.input` | 工具参数，按 `interceptor/tool_schema.json` 转换类型：number 转为 `decimal`，integer 转为 `Long`，array 转为 `Set`，object 转为 `Record`，`null` 字段省略 |
| `context.system.now` | 当前 UTC 时间（Cedar `datetime`） |

Gateway 的 JWT 授权器已在 Interceptor 执行前校验过令牌的签名、签发方、audience 和有效期，
所以 Interceptor 直接解码令牌读取声明，不再重复验签。

### 多条策略如何生效

- **一个文件一条策略。** 每个 `.cedar` 文件就是一条策略，对应海外的一次 CreatePolicy。
  例如场景 05 有 6 条策略。一个文件里写了多条语句时，加载会失败，所有调用都会被拒绝。
- **同一目录的策略一起判定。** Interceptor 把目录下所有文件合成一个 Cedar 策略集，按 Cedar 标准语义整体求值：
  没有 permit 匹配则拒绝；任一 permit 匹配则放行；任一 forbid 匹配则拒绝，且优先于 permit。
  这与 Policy in AgentCore 对引擎内全部策略一起求值的逻辑相同，结果与策略的书写顺序无关。
- **拒绝原因可追溯。** forbid 命中时，错误信息写出对应的文件名，例如
  `Policy evaluation denied due to forbid-delete-claim`。Policy in AgentCore 在同一位置写的是策略 ID。
- **同一时间只有一个目录生效。** 由 Lambda 环境变量 `POLICY_SCENARIO` 指定。
  需要同时生效的规则请放在同一个目录，相当于一个 Gateway 挂一个策略引擎。
- **多个 Gateway 各部署一个 Interceptor。** 每个 Interceptor 只认自己 Gateway 的 ARN。

### 自定义策略

1. 新建目录 `interceptor/policies/<你的场景>/`，每条策略写成一个 `.cedar` 文件。
   resource 请写成 `AgentCore::Gateway::"{{GATEWAY_ARN}}"`。
2. 在同目录写 `tests.json`（期望的 ALLOW / DENY）和 `tools_list.json`（期望可见的工具）。
3. 本地验证：

   ```bash
   python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
   .venv/bin/pytest            # 离线运行全部场景的期望矩阵，不访问 AWS
   ```

4. `scripts/deploy.sh` 重新打包部署，再运行 `scripts/demo.sh <你的场景>`。

`scripts/switch_scenario.py <场景>` 可以只切换生效的场景、不重新部署。它修改的是 Interceptor 的环境变量，
所选场景必须已经打包在部署包里。

## 可选：海外对照组

想亲眼对比 Interceptor 与 Policy in AgentCore 的判定，可以在海外区域部署对照组：

1. 在 `config.env` 中设置 `ENABLE_GLOBAL=true`，并把 `GLOBAL_PROFILE`、`GLOBAL_REGION` 指向你的海外账号。
2. 运行 `scripts/deploy.sh`，会额外部署 Policy in AgentCore 策略引擎和一套相同的 Gateway。
3. 运行 `scripts/demo.sh`，每个场景都会把策略同时加载到两边，并逐行对比。

Policy in AgentCore 在严格校验模式下，会把无条件的 permit 或 forbid 判为过度宽松或过度严格而拒绝创建。
这正是演示所需的语义，因此切换脚本遇到这类分析告警时会打印出来，然后以忽略告警的模式重建。
语法或类型错误仍会直接报错。

## 与 Policy in AgentCore 的差异

| 能力 | 本示例 |
|---|---|
| `tools/call` 放行与拦截、`tools/list` 过滤 | 支持，5 个场景实测一致 |
| permit / forbid、参数条件、时间条件、JWT 声明条件 | 支持 |
| 临时（temporal）策略，即依据会话内历史调用判定 | 不支持。需要按会话保存状态，例如以会话 ID 为键存入 DynamoDB |
| Guardrail 策略、LOG_ONLY 模式 | 不支持 |
| 创建策略时的语法、类型检查与宽松度分析 | 不支持。请用 `pytest` 在部署前验证；策略写错时运行时会一律拒绝 |
| 策略管理 API（CreatePolicy 等） | 无。策略随代码管理，修改后重新部署 |
| IAM 认证的 Gateway（`AgentCore::IamEntity` 主体） | 未实现。实测中 IAM 认证时拦截器事件的 `mcp.gatewayRequest.context.identity.awsPrincipalArn` 带有调用者 ARN，可据此扩展 |
| HTTP 目标、推理目标 | 未覆盖，它们的拦截器载荷格式不同 |

另外，每个 Gateway 最多只能配置一个 REQUEST 拦截器和一个 RESPONSE 拦截器，本示例两个都占用了。
如还需要其他请求改写逻辑，请合并进同一个 Lambda。
`tools/list` 过滤依赖 Cedar 的部分求值功能，上游将其标记为实验特性；`tools/call` 的最终判定始终使用完整求值。

## 安全说明

- Client Secret 只保存在 Secrets Manager 中，由专用 KMS 密钥加密，仅允许经由 Secrets Manager 使用该密钥。
  它的轮换由身份提供方负责，请在 IdP 侧轮换后重新运行 `OIDC_CLIENT_SECRET=<新值> scripts/deploy.sh`。
- Gateway 执行角色只能调用本示例的两个 Lambda 函数。Interceptor 不需要额外的 AWS 权限。
- Interceptor 不记录请求头和令牌，只记录判定结果、主体和动作。
- Gateway 的 `ExceptionLevel` 为 DEBUG，便于演示时查看错误详情。用于生产时请去掉该设置。

## 清理

```bash
scripts/destroy.sh
```

会删除本示例在中国区（以及启用时的海外区）创建的全部堆栈、部署包和策略。
KMS 密钥会进入 CloudFormation 默认的待删除期。

## 目录结构

```
interceptor/            Interceptor Lambda：handler.py（拦截逻辑）、cedar_mapping.py（请求映射）
  policies/<场景>/       Cedar 策略（每文件一条）与期望结果
  tool_schema.json      工具参数定义，用于类型转换；测试保证与模板中的定义一致
tools/claims_tool/      模拟的保险理赔工具（Gateway 的 Lambda 目标）
infra/                  CloudFormation 模板：template.yaml（Gateway 堆栈）、artifacts.yaml、policy-engine.yaml
scripts/                deploy.sh、demo.sh、destroy.sh 及其 Python 辅助脚本
tests/                  离线单元测试与场景期望矩阵
```

## 常见问题

**部署时卡在下载 cedarpy。** 设置 `PIP_INDEX_URL` 使用国内 PyPI 镜像后重试。

**申请测试令牌失败。** 检查 `OIDC_DISCOVERY_URL`、`OIDC_CLIENT_ID`、`OIDC_AUDIENCE`，以及 Auth0 中该应用是否已获授权访问对应 API。
Client Secret 输错时，用 `OIDC_CLIENT_SECRET=<正确值> scripts/deploy.sh` 重新部署即可更新。

**场景 05 中个别结果与期望不符。** 该场景按 Auth0 client_credentials 令牌的声明设计（`scope`、`gty`）。
换用其他身份提供方时，请按实际令牌内容调整策略和 `tests.json`。

**想部署到宁夏区域。** 在 `config.env` 中设置 `CN_REGION=cn-northwest-1`。

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
