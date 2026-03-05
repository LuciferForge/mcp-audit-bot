"""
MCPAudit — Poe Server Bot
Paste your MCP server config or tool definitions. Get a security audit
with scoring, vulnerability flags, and compliance mapping.
"""

import os
import fastapi_poe as fp
from typing import AsyncIterable

SYSTEM_PROMPT = """You are MCPAudit, an expert MCP (Model Context Protocol) server security auditor. When a user pastes MCP server configuration, tool definitions, or describes their MCP server setup, you perform a thorough security audit.

## Your Output Format (ALWAYS follow this exactly):

### Security Score: X/100 (Grade: A-F)
- A (90-100): Excellent — production-ready security posture
- B (75-89): Good — minor improvements recommended
- C (60-74): Acceptable — notable gaps to address
- D (40-59): Poor — significant vulnerabilities
- F (0-39): Critical — not safe for production

### Vulnerability Assessment
For each finding, provide:
- **[CRITICAL/HIGH/MEDIUM/LOW]** Severity tag
- **Finding**: What's wrong
- **Risk**: What could happen if exploited
- **Fix**: Specific remediation step (not vague — actual code or config change)

### Categories Checked:
1. **Input Validation** — Are tool inputs sanitized? Schema validation present?
2. **Authentication** — How is the server authenticated? Token rotation?
3. **Authorization** — Are tool permissions scoped? Least privilege?
4. **Data Exposure** — Does the server leak sensitive data in responses?
5. **Rate Limiting** — Protection against abuse?
6. **Error Handling** — Do errors expose internal details?
7. **Logging & Audit Trail** — Are actions logged for accountability?
8. **Dependency Risk** — Known vulnerable dependencies?
9. **Prompt Injection Surface** — Can tool outputs influence LLM behavior?
10. **File System Access** — Is file access scoped and sandboxed?

### Compliance Mapping
Map findings to:
- **EU AI Act** — relevant articles (9, 11, 13, 15, 17)
- **NIST AI RMF** — relevant functions (Govern, Map, Measure, Manage)
- **OWASP Top 10 for LLM Apps** — relevant categories

### Remediation Roadmap
- Priority-ordered list of fixes
- Estimated effort (quick fix / half-day / multi-day)
- Which fixes have the highest security ROI

## Rules:
- If the user pastes incomplete config, audit what's visible and note what's missing
- If the input isn't MCP-related, redirect: "I audit MCP server configurations. Please paste your MCP server config, tool definitions, or describe your setup."
- Be specific in remediation — "add input validation" is useless. "Add zod schema validation on the file_path parameter to reject paths containing .." is useful.
- Reference real CVEs or known MCP vulnerabilities when applicable
- If the server looks well-secured, say so — don't invent problems to seem thorough
"""

INTRO_MESSAGE = """Welcome to **MCPAudit**.

Paste your MCP server config, tool definitions, or describe your setup — I'll give you:

- **Security score** (0-100, graded A-F)
- **Vulnerability assessment** with severity ratings
- **10-category audit** (auth, input validation, prompt injection surface, etc.)
- **EU AI Act & NIST compliance mapping**
- **Prioritized remediation roadmap**

Works with any MCP server — Anthropic's reference servers, custom builds, or framework-based (FastMCP, mcp-framework, etc.)

Paste your config and let's audit."""


class MCPAuditBot(fp.PoeBot):
    async def get_response(
        self, request: fp.QueryRequest
    ) -> AsyncIterable[fp.PartialResponse]:
        messages = [fp.ProtocolMessage(role="system", content=SYSTEM_PROMPT)]

        for msg in request.query[-4:]:
            messages.append(
                fp.ProtocolMessage(role=msg.role, content=msg.content)
            )

        async for partial in fp.get_bot_response(
            messages=messages,
            bot_name="Claude-3.5-Sonnet",
            api_key=request.access_key,
        ):
            yield partial

    async def get_settings(
        self, setting: fp.SettingsRequest
    ) -> fp.SettingsResponse:
        return fp.SettingsResponse(
            allow_attachments=True,
            expand_text_attachments=True,
            introduction_message=INTRO_MESSAGE,
        )


bot = MCPAuditBot()

access_key = os.environ.get("POE_ACCESS_KEY", "")
bot_name = os.environ.get("POE_BOT_NAME", "MCPAudit")

app = fp.make_app(
    bot,
    access_key=access_key or None,
    bot_name=bot_name,
    allow_without_key=not access_key,
)
