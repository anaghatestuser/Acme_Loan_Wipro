"""Scheduling Agent class with explicit model invocation."""
# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
# Each enforce() call site below carries a SiteDescriptor with:
#   site_id            deterministic id for this exact call site (file +
#                      symbol + insertion point + pattern) — stable across
#                      re-scans, used to dedupe stub insertions and to look
#                      up this site's policy mapping at runtime.
#   candidate_policies policy IDs this site matched during the scan.
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _s, importlib.util as _ilu
    from pathlib import Path as _P
    n = "_lineaje_gr_stub_client"
    if n in _s.modules: return _s.modules[n]
    h = _P(__file__).resolve().parent
    _cand = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), h / "gr_stub_client.py")
    _spec = _ilu.spec_from_file_location(n, _cand)
    _s.modules[n] = _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m); return _m


import asyncio
from typing import Any

from .framework import AcmeLoanAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server


class SchedulingAgent(AcmeLoanAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon nova lite"
    BEDROCK_MODEL_ID = "amazon.nova-lite-v1:0"
    DESCRIPTION = "Schedules borrower, underwriting, and support meetings."
    MCP_SERVERS = ["Google Calendar", "Email", "Slack"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Coordinate calendar events and notify the relevant teams."

    async def call_agent_model(self, user_message: str, meeting_reference: str) -> str:
        _lineaje_messages = ([
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Meeting reference: {meeting_reference}\n"
                        f"Scheduling request: {user_message or 'Loan coordination meeting requested.'}\n\n"
                        "Draft a scheduling confirmation."
                    ),
                },
            ])
        # LINEAJE: enforce() `_lineaje_messages` at html->user_interface data_egress — scan flagged AI_APP_SEC_038 (The AI Model must validate and sanitize any input before processing.); AI_APP_SEC_059 (Do not allow prompts that can execute malicious commands at runtime.); AI_IAC_024 (General purpose AI model integrations must reference a model card or technical documentation). Mask/block; do not remove without review. site_id='site:sha256:5c5c484168ccb5c0f2ed8bfa6811e7d8ee57fc2e5aab147ae5acd0468f4240eb'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5c5c484168ccb5c0f2ed8bfa6811e7d8ee57fc2e5aab147ae5acd0468f4240eb', phase='data_egress', boundary={'source': 'html', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_038', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_059', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_024', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='html', destination_type='user_interface')
        _lineaje_messages = _gr_client.enforce(_gr_site, _lineaje_messages, content_type='text/html')
        return await self.call_bedrock_model(
            messages=_lineaje_messages,
            temperature=0.2,
            max_tokens=180,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        meeting_reference = extract_reference_number(user_message, prefix="MEET")
        # LINEAJE: enforce() `user_message` at html->user_interface data_egress — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_039 (Sanitize and validate all input to the AI Model.). Mask/block; do not remove without review. site_id='site:sha256:617f6fbd5f056e64be4dd3e42c619b0cbc3af2ed3baf169ace9a746cb3b5b3a8'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:617f6fbd5f056e64be4dd3e42c619b0cbc3af2ed3baf169ace9a746cb3b5b3a8', phase='data_egress', boundary={'source': 'html', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_029', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_039', 'guardrail_id': None, 'policy_version': None}], fail_mode='BLOCK', source_type='html', destination_type='user_interface')
        user_message = _gr_client.enforce(_gr_site, user_message, content_type='text/html')
        model_output = await self.call_agent_model(user_message, meeting_reference)

        mcp_activity = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {meeting_reference}",
                    "description": user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {meeting_reference}.",
                },
            ),
        )

        response = (
            f"Meeting reference: {meeting_reference}\n"
            f"Scheduling request: {user_message or 'No scheduling request provided.'}\n\n"
            f"Scheduling summary:\n{model_output}"
        )
        # LINEAJE: enforce() `response` at html->user_interface data_egress — scan flagged AI_APP_SEC_006 (Use only LLMs from the organization's approved list.); AI_APP_SEC_023 (Client must validate and sanitize any output from a MCP server); AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.). Mask/block; do not remove without review. site_id='site:sha256:0a35bece3b5c5938aefc3769c11b2447500a9a9c1a9bbe13c44e113409dad54b'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0a35bece3b5c5938aefc3769c11b2447500a9a9c1a9bbe13c44e113409dad54b', phase='data_egress', boundary={'source': 'html', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_006', 'guardrail_id': 'Enforce Approved LLM.', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_APP_SEC_023', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_029', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_038', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_039', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_059', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_067', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_APP_SEC_070', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_025', 'guardrail_id': 'If a file contains PII, redact the PII', 'policy_version': '2026.08.1'}, {'policy_id': 'AI_IAC_014', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_023', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_IAC_024', 'guardrail_id': None, 'policy_version': None}, {'policy_id': 'AI_DAT_SEC_027', 'guardrail_id': 'Minimise and redact all outbound AI outputs.', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='html', destination_type='user_interface')
        response = _gr_client.enforce(_gr_site, response, content_type='text/html')

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


scheduling_agent = SchedulingAgent()
