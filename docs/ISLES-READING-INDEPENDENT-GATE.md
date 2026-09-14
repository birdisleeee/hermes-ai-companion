# 共读岛 Gateway 独立联调候选闸门

2026-09-14。仅限全新候选目录、临时 HERMES_HOME 和 loopback 测试。不是上线授权，也不是生产就绪声明。

## 候选身份

分支为 `feature/isles-reading-island-gateway`。以 Codex 交付的完整 SHA checkout detached，记录 HEAD、tree、工作树 clean 和相对生产 `faa16c26b0509e4b7eabb884dd4d847bb7e3c79b` 的 diff。
本分支从 `4d3e6d3` 分出，包含共读契约提交及热修的 cherry-pick `63811a5`，因此 parent **不是** faa16c26。两个热修文件相对 faa16c26 应为零差异：`tools/isles_sticker_tool.py`、`tests/gateway/test_isles_sticker_reply.py`。不能按 parent 相等误判，也不能只看短 SHA。

## 测试命令（Linux，在全新候选目录）

使用已经安装 pytest、pytest-asyncio、aiohttp 的 Python 绝对路径替换 PYTHON。可以借用现有 venv 的解释器，不安装或修改其依赖。先 `unset PYTHONPATH`，由当前候选目录导入代码，打印 `gateway.__file__` 核对，不输出环境变量内容。

```bash
unset PYTHONPATH
export HERMES_HOME="$(mktemp -d /tmp/isles-reading-gate-XXXXXXXX)"
export PYTHONDONTWRITEBYTECODE=1
PYTHON -c 'import gateway; print(gateway.__file__)'
PYTHON -m pytest -q -p no:cacheprovider tests/gateway/test_isles_reading_contract.py tests/gateway/test_isles_reading_network.py
PYTHON -m pytest -q -p no:cacheprovider tests/gateway/test_webhook_adapter.py tests/gateway/test_isles_sticker_reply.py tests/gateway/test_isles_story_tool_permissions.py tests/gateway/test_isles_context_window_session.py tests/gateway/test_isles_media_and_segmentation.py
```

命令中的 `PYTHON` 是解释器路径占位符，不能原样执行。不要复制生产 config、.env、SOUL、USER、脑库、session 或 registry 到临时 HOME。不要启动完整 Gateway daemon 或真实模型。网络测试自动使用 127.0.0.1 随机空闲端口，退出即关闭；不会绑定 8764/8644/8645，也不要求固定使用 8870。

本机 Windows 回归中 `default_bind_rejects_existing_ipv6_listener` 曾失败后单独排除；Linux **不得排除**，请运行并报告结果。任何其他失败必须报告，不通过改测试、改生产配置或删除记录绕过。

## 临时 route 字段说明

测试代码直接创建 PlatformConfig / WebhookAdapter，不需要写 config.yaml。若后续联合夹具需要构造等价配置，结构如下；端口必须换成临时接收端实际端口，字符串只是虚构测试凭据：

```yaml
platforms:
  webhook:
    enabled: true
    extra:
      host: 127.0.0.1
      port: 8870
      routes:
        isles-reading:
          secret: isolated-reading-fixture-only
          deliver: http_callback
          deliver_extra:
            url: http://127.0.0.1:8871/api/reading/gateway/reply
          reply_delivery:
            segmented: true
            hard_split_marker: '<BREAK>'
```

不要配置 profile、skill、transform 或 deliver_only。该片段不是生产配置，不要写入生产 HERMES_HOME。共读候选使用 route secret 对 reply/status 做 V2 HMAC，同一凭据用于 source 的 Bearer；当前共读代码不从 deliver_extra.token 取回调签名。status/source 默认分别由固定 reply 路径派生为 `/api/reading/gateway/status` 和 `/api/reading/gateway/source`。临时接收端需实现这些路径；`test_isles_reading_network.py` 只实现 status/reply，原文工具由 contract 测试独立验证。

## 会话与提示挂点

- 入站 `/webhooks/isles-reading`；V2 timestamp HMAC，X-Request-ID 等于 payload.delivery_id，turn_id 与 delivery_id 分开。
- `validate_reading_turn` 验证身份，session 固定为 `webhook:isles-reading:<thread_id>`；同议题连续，不同议题独立。
- `_handle_webhook` 调用 `build_reading_prompt`，不使用通用 prompt 模板解释书籍内容。用户本人和既有桔小鸟正常聊天，延续关系与称呼；不注入“岛主”角色，不新建人格。
- 初始输入只有书名/作者、议题、核验摘录及想法、用户发言、版本绑定 source_link；没有整章/整本原文。
- `_run_agent` 在当前 turn 的 `isles_reading_turn_scope` 内开放 `read_isles_reading_source`；每次最多 4000 单位，不能读取其他议题链接。权限 route 名称不代表用户人格。
- `_emit_isles_processing_status` 回传固定讨论标识，不把 Hermes 内部 transcript UUID 当作 Worker session。
- send(reply_to=turn_id) 从 turn 快照取 delivery，回复按现有分段器生成一次带全部 Markdown actions 的回调。Worker 承担原子消息落库。

## 报告及限制

后续候选新增验证：HTTP 接收端先返回 503，新建没有内存 delivery snapshot 的适配器，实际调用 connect() 自动恢复磁盘 outbox，再次回调正文及身份与第一次逐字相同；未完成推理标为 interrupted/retryable，isles-story 测试记录保持原样。此测试是同进程重新构造适配器，不是杀死并重启独立 OS 进程，不能据此宣称跨进程崩溃恢复已验收。须针对新候选重新运行服务器闸门。

报告候选身份、导入位置、定向/回归完整统计、HTTP 三回合两议题乱序回调结果、临时 HOME 路径和生产前后指纹。只回报脱敏信息。
当前测试中的模型/Worker 接收端是替身；它不证明浏览器→CF候选→Hermes→CF 的完整联合链路，也不证明真实人格加载、模型回应或 iPhone 验收。Gateway 重启恢复、FIFO 超限、回调失败重试与跨进程联合闸门仍需进一步验证；通过本轮也不得声明可直接上线。
不得 restart、改 unit、生产 config、Secret、Tunnel、Worker、R2、session 或沈初服务。闸门完成后停在报告阶段。
