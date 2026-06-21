"""演示用 fixture 数据。

数据严格对齐 docs/design/ui-flow/desktop-macos/ 各设计图（Hermes/OpenClaw、
MCP/Skills/知识库、暴露面 8 项、组件 CVE、权限分布等）。

MVP 阶段 Discovery/Detector 以本文件驱动端到端；后续接入 pyATR / OSV /
真实 Adapter 时，由各模块产出同形态对象替换之。
"""

from __future__ import annotations

from ..models import (
    Agent,
    Asset,
    AssetStatus,
    AssetType,
    CVEFinding,
    CVEItem,
    ExposureFinding,
    FindingSource,
    PermissionEntry,
    Severity,
)

S = Severity
ST = AssetStatus
AT = AssetType
SRC = FindingSource


def _perm(pid, name, category, source, source_label, severity):
    return PermissionEntry(
        id=pid,
        name=name,
        category=category,
        source=source.value,
        source_label=source_label,
        severity=severity.value,
    )


def build_agents():
    return [
        Agent(
            id="hermes",
            name="Hermes Agent",
            kind="hermes",
            version="v1.2.0",
            latest_version="v1.3.0",
            listen_ports=["8080"],
            enabled=True,
            description="通用智能体，擅长任务规划与工具调用",
            permissions=[
                _perm("a-h-file", "读取本地文件", "文件", SRC.AGENT_CONFIG, "Agent 默认", S.HIGH),
                _perm("a-h-shell", "执行 Shell 命令", "Shell", SRC.AGENT_CONFIG, "Agent 默认", S.HIGH),
                _perm("a-h-net", "访问外部网络", "网络", SRC.AGENT_CONFIG, "Agent 默认", S.MEDIUM),
            ],
        ),
        Agent(
            id="openclaw",
            name="OpenClaw",
            kind="openclaw",
            version="v0.9.1",
            latest_version="v0.9.1",
            listen_ports=["18789"],
            enabled=True,
            description="安全研究专用智能体，专注漏洞分析与利用",
            permissions=[
                _perm("a-o-shell", "执行 Shell 命令", "Shell", SRC.AGENT_CONFIG, "Agent 默认", S.HIGH),
                _perm("a-o-net", "访问外部网络", "网络", SRC.AGENT_CONFIG, "Agent 默认", S.MEDIUM),
                _perm("a-o-file", "读取本地文件", "文件", SRC.AGENT_CONFIG, "Agent 默认", S.MEDIUM),
            ],
        ),
    ]


def build_assets():
    assets = []

    # ---- Hermes: 3 MCP / 5 Skills / 2 知识库 ----
    assets.append(Asset(
        id="hermes-mcp-filesystem", agent_id="hermes", type=AT.MCP.value,
        name="filesystem", version="1.2.3", status=ST.ENABLED.value,
        purpose="本地文件读写访问", source="Hermes",
        permissions=[_perm("p-fs-file", "读写文件", "文件", SRC.MCP, "filesystem MCP", S.MEDIUM)],
        can_update=False,
    ))
    assets.append(Asset(
        id="hermes-mcp-shell", agent_id="hermes", type=AT.MCP.value,
        name="shell", version="1.1.0", latest_version="1.2.0",
        status=ST.UPDATABLE.value,
        purpose="远程命令执行，支持在目标主机上执行 shell 命令并返回结果。",
        source="Hermes",
        permissions=[
            _perm("p-sh-shell", "执行命令、管理进程", "Shell", SRC.MCP, "shell MCP", S.HIGH),
            _perm("p-sh-net", "访问内网、外网", "网络", SRC.MCP, "shell MCP", S.MEDIUM),
            _perm("p-sh-file", "读取、写入、创建、删除", "文件", SRC.MCP, "shell MCP", S.HIGH),
        ],
        can_update=True,
    ))
    assets.append(Asset(
        id="hermes-mcp-browser", agent_id="hermes", type=AT.MCP.value,
        name="browser", version="0.9.5", status=ST.DISABLED.value,
        purpose="无头浏览器自动化与网页抓取", source="Hermes",
        permissions=[_perm("p-br-net", "发起网络请求", "网络", SRC.MCP, "browser MCP", S.LOW)],
        can_update=False,
    ))
    assets.append(Asset(
        id="hermes-skill-web-search", agent_id="hermes", type=AT.SKILL.value,
        name="Web Search Skill", version="1.1.0", latest_version="1.2.0",
        status=ST.UPDATABLE.value,
        purpose="联网搜索并汇总结果", source="Hermes",
        permissions=[_perm("p-ws-net", "网络搜索", "网络", SRC.SKILL, "Web Search Skill", S.LOW)],
        can_update=True,
    ))
    assets.append(Asset(
        id="hermes-skill-python-runner", agent_id="hermes", type=AT.SKILL.value,
        name="Python Runner Skill", version="2.0.0", status=ST.ENABLED.value,
        purpose="执行 Python 代码片段", source="Hermes",
        permissions=[_perm("p-py-exec", "代码执行 (Python)", "工具", SRC.SKILL, "Python Runner Skill", S.HIGH)],
    ))
    for sid, nm, ver in [
        ("hermes-skill-summarizer", "File Summarizer Skill", "1.0.0"),
        ("hermes-skill-code-review", "Code Review Skill", "1.3.0"),
        ("hermes-skill-translator", "Translator Skill", "0.8.0"),
    ]:
        assets.append(Asset(
            id=sid, agent_id="hermes", type=AT.SKILL.value, name=nm,
            version=ver, status=ST.ENABLED.value, purpose="辅助技能", source="Hermes",
        ))
    assets.append(Asset(
        id="hermes-kb-github", agent_id="hermes", type=AT.KNOWLEDGE.value,
        name="GitHub Knowledge", version="1.0.3", latest_version="1.1.0",
        status=ST.UPDATABLE.value, purpose="GitHub 仓库知识库", source="Hermes",
        permissions=[_perm("p-kb-read", "读取知识库内容", "知识库", SRC.KNOWLEDGE, "GitHub Knowledge", S.LOW)],
        can_update=True,
    ))
    assets.append(Asset(
        id="hermes-kb-docs", agent_id="hermes", type=AT.KNOWLEDGE.value,
        name="Docs Knowledge", version="1.0.0", status=ST.ENABLED.value,
        purpose="远程文档知识库", source="Hermes",
        permissions=[_perm("p-kb-dl", "下载远程内容", "知识库", SRC.KNOWLEDGE, "Docs Knowledge", S.LOW)],
    ))
    assets.append(Asset(
        id="hermes-channel-webchat", agent_id="hermes", type=AT.CHANNEL.value,
        name="WebChat", version="pairing", status=ST.ENABLED.value,
        purpose="WebChat IM 通道（DM 策略 pairing）", source="Hermes",
        permissions=[_perm("ch-h-wc", "访问外部网络", "网络", SRC.AGENT_CONFIG, "WebChat", S.MEDIUM)],
        path="~/.hermes/config.yaml", config_key="platforms:webchat",
        can_disable=True, can_uninstall=False, can_update=False,
    ))
    assets.append(Asset(
        id="hermes-channel-feishu", agent_id="hermes", type=AT.CHANNEL.value,
        name="飞书", version=None, status=ST.DISABLED.value,
        purpose="飞书 IM 通道", source="Hermes",
        permissions=[_perm("ch-h-fs", "访问外部网络", "网络", SRC.AGENT_CONFIG, "飞书", S.MEDIUM)],
        path="~/.hermes/config.yaml", config_key="platforms:feishu",
        can_disable=True, can_uninstall=False, can_update=False,
    ))

    # ---- OpenClaw: 2 MCP / 3 Skills ----
    assets.append(Asset(
        id="openclaw-mcp-http", agent_id="openclaw", type=AT.MCP.value,
        name="HTTP MCP", version="1.0.0", status=ST.ENABLED.value,
        purpose="发起 HTTP 网络请求", source="OpenClaw",
        permissions=[_perm("p-http-net", "发起网络请求", "网络", SRC.MCP, "HTTP MCP", S.LOW)],
    ))
    assets.append(Asset(
        id="openclaw-mcp-postgres", agent_id="openclaw", type=AT.MCP.value,
        name="PostgreSQL MCP", version="0.9.1", status=ST.ENABLED.value,
        purpose="读取数据库", source="OpenClaw",
        permissions=[_perm("p-pg-db", "读数据库", "工具", SRC.MCP, "PostgreSQL MCP", S.MEDIUM)],
    ))
    for sid, nm, ver in [
        ("openclaw-skill-exploit", "Exploit Analyzer Skill", "1.0.0"),
        ("openclaw-skill-vuln", "Vuln Scanner Skill", "1.2.0"),
        ("openclaw-skill-report", "Report Generator Skill", "0.5.0"),
    ]:
        assets.append(Asset(
            id=sid, agent_id="openclaw", type=AT.SKILL.value, name=nm,
            version=ver, status=ST.ENABLED.value, purpose="安全研究技能", source="OpenClaw",
        ))
    assets.append(Asset(
        id="openclaw-channel-slack", agent_id="openclaw", type=AT.CHANNEL.value,
        name="Slack", version="socket", status=ST.ENABLED.value,
        purpose="Slack IM 通道（模式 socket；凭证引用：botToken, appToken）", source="OpenClaw",
        permissions=[_perm("ch-o-slack", "访问外部网络", "网络", SRC.AGENT_CONFIG, "Slack", S.MEDIUM)],
        path="~/.openclaw/openclaw.json", config_key="channels:slack",
        can_disable=True, can_uninstall=False, can_update=False,
    ))
    assets.append(Asset(
        id="openclaw-channel-webchat", agent_id="openclaw", type=AT.CHANNEL.value,
        name="WebChat", version=None, status=ST.DISABLED.value,
        purpose="WebChat IM 通道", source="OpenClaw",
        permissions=[_perm("ch-o-wc", "访问外部网络", "网络", SRC.AGENT_CONFIG, "WebChat", S.MEDIUM)],
        path="~/.openclaw/openclaw.json", config_key="channels:webchat",
        can_disable=True, can_uninstall=False, can_update=False,
    ))

    # ---- 依赖（供 CVE 视图，使用 OSV 可解析的真实坐标）----
    # (agent, 名称, 版本, ecosystem)
    deps = [
        # Hermes —— npm 生态
        ("hermes", "lodash", "4.17.11", "npm"),
        ("hermes", "axios", "0.21.0", "npm"),
        ("hermes", "minimist", "1.2.0", "npm"),
        ("hermes", "fastify", "4.17.1", "npm"),
        # OpenClaw —— PyPI / Maven 生态
        ("openclaw", "pyyaml", "5.3", "PyPI"),
        ("openclaw", "requests", "2.19.1", "PyPI"),
        ("openclaw", "jinja2", "2.10", "PyPI"),
        ("openclaw", "django", "2.2", "PyPI"),
        ("openclaw", "org.apache.logging.log4j:log4j-core", "2.14.1", "Maven"),
    ]
    for agent_id, nm, ver, eco in deps:
        assets.append(Asset(
            id="dep-" + nm, agent_id=agent_id, type=AT.DEPENDENCY.value,
            name=nm, version=ver, status=ST.ENABLED.value,
            purpose=eco + " 依赖组件", source=agent_id, ecosystem=eco,
            can_disable=False, can_uninstall=False,
        ))

    return assets


def build_exposure_findings():
    """对齐 step4-security-issues-list.png 的 8 项基础检查。"""
    return [
        ExposureFinding(
            id="ATR-2025-00012", title="未授权的外网访问", severity=S.HIGH.value,
            category="网络暴露", source=SRC.AGENT_CONFIG.value,
            agent_ids=["hermes", "openclaw"],
            impact="Agent 可在无认证情况下访问任意外部网络地址，可能被诱导发起 SSRF 或数据外传。",
            evidence='network.allow_outbound: "*"\nauth: none  (agent-config.yaml:8)',
            recommendation="限制可访问的外部域名白名单，并为外网访问开启认证。",
            plain_explanation="这个 AI 助手当前可以随意联网，建议只允许它访问必要的网站，更安全。",
            location="agent-config.yaml:8",
            tags=["OWASP-LLM01", "网络"],
        ),
        ExposureFinding(
            id="ATR-2025-00034", title="MCP权限过宽", severity=S.MEDIUM.value,
            category="权限与访问控制", source=SRC.MCP.value,
            agent_ids=["hermes"],
            impact="攻击者或恶意指令 (Prompt) 可能利用过宽权限读取敏感数据、执行敏感操作或访问不必要的系统资源，造成数据泄露或环境被控制。",
            evidence=(
                '{\n'
                '  "mcp_server": "filesystem-server",\n'
                '  "granted_permissions": ["read", "write", "delete", "exec"],\n'
                '  "path": "/",\n'
                '  "configured_by": "agent-config.yaml:12"\n'
                '}'
            ),
            recommendation="遵循最小权限原则，收窄 MCP 服务器权限范围，仅授予必要的读写或执行权限，并限制访问路径。",
            plain_explanation="这个问题的意思是：当前配置给了 AI 助手太多的「操作权限」，可能让它做了不该做的事情，比如删除文件、改系统设置等。建议只给它完成任务所需的权限，更安全。",
            location="agent-config.yaml:12",
            tags=["OWASP-LLM06", "权限"],
        ),
        ExposureFinding(
            id="ATR-2025-00041", title="缺少输入验证", severity=S.MEDIUM.value,
            category="输入校验", source=SRC.MCP.value, agent_ids=["hermes"],
            impact="工具入参未校验，可能被注入恶意参数。",
            evidence="tool.parameters: 未声明 schema (mcp.json:23)",
            recommendation="为工具参数声明 schema 并做白名单校验。",
            plain_explanation="助手调用工具时没有检查输入内容，容易被钻空子，建议加上检查。",
            location="mcp.json:23",
        ),
        ExposureFinding(
            id="ATR-2025-00052", title="日志级别过高", severity=S.LOW.value,
            category="日志与审计", source=SRC.AGENT_CONFIG.value, agent_ids=["openclaw"],
            impact="DEBUG 级日志可能写入敏感信息。",
            evidence='log.level: "debug" (openclaw.json:5)',
            recommendation="生产环境降低日志级别至 info 或以上。",
            plain_explanation="日志记录得太详细，可能把敏感信息写进文件，建议调低。",
            location="openclaw.json:5",
        ),
        ExposureFinding(
            id="ATR-2025-00067", title="敏感信息未加密", severity=S.MEDIUM.value,
            category="数据安全", source=SRC.AGENT_CONFIG.value, agent_ids=["openclaw"],
            impact="检测到配置中以明文形式引用凭证。",
            evidence="api_key: <检测到引用，前4位 sk-x…>  (openclaw.json:14)",
            recommendation="将凭证迁移至系统钥匙串或环境变量，避免明文落盘。",
            plain_explanation="密码或密钥是明文存的，建议改成加密保存。",
            location="openclaw.json:14",
        ),
        ExposureFinding(
            id="ATR-2025-00071", title="容器以 root 用户运行", severity=S.LOW.value,
            category="容器安全", source=SRC.AGENT_CONFIG.value, agent_ids=["openclaw"],
            impact="容器逃逸后可获得宿主 root 权限。",
            evidence="user: root (Dockerfile:1)",
            recommendation="使用非特权用户运行容器。",
            plain_explanation="程序以最高权限运行，风险较大，建议降权。",
            location="Dockerfile:1",
        ),
        ExposureFinding(
            id="ATR-2025-00078", title="未设置资源限制", severity=S.LOW.value,
            category="资源与配额", source=SRC.AGENT_CONFIG.value, agent_ids=["hermes"],
            impact="无 CPU/内存限制，可能被拖垮。",
            evidence="resources.limits: 未声明",
            recommendation="为运行环境设置资源上限。",
            plain_explanation="没有限制助手能用多少资源，极端情况下可能拖慢电脑。",
            location="agent-config.yaml:30",
        ),
        ExposureFinding(
            id="ATR-2025-00085", title="未启用审计日志", severity=S.LOW.value,
            category="审计与合规", source=SRC.AGENT_CONFIG.value, agent_ids=["hermes", "openclaw"],
            impact="无操作审计，事后难以追溯。",
            evidence="audit.enabled: false",
            recommendation="开启关键操作审计日志。",
            plain_explanation="没有记录助手都做了什么，出问题不好追查，建议打开记录。",
            location="agent-config.yaml:40",
        ),
    ]


def build_cve_findings():
    """对齐 step4-component-issues-list.png。"""
    return [
        CVEFinding(
            id="cve-openclaw-core", component="openclaw-core", component_type="Maven",
            current_version="1.3.2", fixed_version="1.3.8", severity=S.HIGH.value,
            agent_ids=["openclaw"], first_seen="2025-05-20",
            upgrade_advice="建议升级到最新安全版本 1.3.8。该版本已修复上述所有已知漏洞，建议尽快升级以保障系统安全。",
            cves=[
                CVEItem("CVE-2024-31756", S.HIGH.value, 9.8, "反序列化漏洞，攻击者可通过构造恶意数据绕过安全限制，执行任意代码。"),
                CVEItem("CVE-2024-31757", S.HIGH.value, 8.6, "权限绕过漏洞，攻击者可绕过认证访问受限资源。"),
                CVEItem("CVE-2024-31758", S.MEDIUM.value, 6.5, "信息泄露漏洞，攻击者可获取敏感信息。"),
                CVEItem("CVE-2024-31759", S.MEDIUM.value, 5.3, "目录遍历漏洞，攻击者可访问任意系统文件。"),
                CVEItem("CVE-2024-31760", S.LOW.value, 3.7, "拒绝服务漏洞，攻击者可通过特定请求导致服务异常。"),
                CVEItem("CVE-2024-31761", S.MEDIUM.value, 6.1, "跨站脚本漏洞。"),
                CVEItem("CVE-2024-31762", S.LOW.value, 3.1, "信息暴露。"),
            ],
        ),
        CVEFinding(
            id="cve-log4j-core", component="log4j-core", component_type="Maven",
            current_version="2.14.1", fixed_version="2.17.1", severity=S.HIGH.value,
            agent_ids=["openclaw"], first_seen="2025-05-18",
            upgrade_advice="升级到 2.17.1 以修复 Log4Shell 系列漏洞。",
            cves=[
                CVEItem("CVE-2021-44228", S.HIGH.value, 10.0, "Log4Shell 远程代码执行。"),
                CVEItem("CVE-2021-45046", S.HIGH.value, 9.0, "RCE / 拒绝服务。"),
                CVEItem("CVE-2021-45105", S.MEDIUM.value, 5.9, "拒绝服务。"),
                CVEItem("CVE-2021-44832", S.MEDIUM.value, 6.6, "JDBC Appender RCE。"),
                CVEItem("CVE-2020-9488", S.LOW.value, 3.7, "证书校验不当。"),
            ],
        ),
        CVEFinding(
            id="cve-fastjson", component="fastjson", component_type="Maven",
            current_version="1.2.68", fixed_version="1.2.83", severity=S.MEDIUM.value,
            agent_ids=["openclaw"], first_seen="2025-05-19",
            upgrade_advice="升级到 1.2.83 并开启 safeMode。",
            cves=[
                CVEItem("CVE-2022-25845", S.MEDIUM.value, 6.5, "autoType 绕过反序列化。"),
                CVEItem("CVE-2020-15170", S.MEDIUM.value, 5.6, "拒绝服务。"),
                CVEItem("CVE-2019-12384", S.LOW.value, 3.5, "信息泄露。"),
            ],
        ),
        CVEFinding(
            id="cve-commons-fileupload", component="commons-fileupload", component_type="Maven",
            current_version="1.3.3", fixed_version="1.5", severity=S.MEDIUM.value,
            agent_ids=["openclaw"], first_seen="2025-05-15",
            upgrade_advice="升级到 1.5。",
            cves=[
                CVEItem("CVE-2023-24998", S.MEDIUM.value, 7.5, "DoS：上传过多分片。"),
                CVEItem("CVE-2016-1000031", S.MEDIUM.value, 6.8, "反序列化 RCE。"),
            ],
        ),
        CVEFinding(
            id="cve-jackson-databind", component="jackson-databind", component_type="Maven",
            current_version="2.9.10", fixed_version="2.15.0", severity=S.LOW.value,
            agent_ids=["openclaw"], first_seen="2025-05-12",
            upgrade_advice="升级到 2.15.0。",
            cves=[CVEItem("CVE-2020-36518", S.LOW.value, 3.7, "嵌套对象 DoS。")],
        ),
        CVEFinding(
            id="cve-netty-all", component="netty-all", component_type="Maven",
            current_version="4.1.42", fixed_version="4.1.86", severity=S.LOW.value,
            agent_ids=["openclaw"], first_seen="2025-05-10",
            upgrade_advice="升级到 4.1.86。",
            cves=[CVEItem("CVE-2021-21290", S.LOW.value, 2.5, "本地临时文件信息泄露。")],
        ),
        CVEFinding(
            id="cve-guava", component="guava", component_type="Maven",
            current_version="30.0", fixed_version=None, severity=S.LOW.value,
            agent_ids=["openclaw"], first_seen="2025-05-08",
            upgrade_advice="暂无需升级。", cves=[],
        ),
        CVEFinding(
            id="cve-h2", component="h2", component_type="Maven",
            current_version="1.4.200", fixed_version=None, severity=S.LOW.value,
            agent_ids=["openclaw"], first_seen="2025-05-06",
            upgrade_advice="暂无需升级。", cves=[],
        ),
        CVEFinding(
            id="cve-fastify", component="fastify", component_type="npm",
            current_version="4.17.1", fixed_version="4.18.0", severity=S.HIGH.value,
            agent_ids=["hermes"], first_seen="2025-05-28",
            upgrade_advice="升级到 4.18.0 修复路径遍历漏洞。",
            cves=[CVEItem("CVE-2024-31999", S.HIGH.value, 7.5, "路径遍历漏洞，攻击者可读取服务端任意文件。")],
        ),
    ]
