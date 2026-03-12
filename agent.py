"""
pyknock/agent.py
────────────────
AI-driven pentesting orchestration loop.
Uses Claude (claude-sonnet-4-20250514) to decide what to run next,
analyse results, and surface findings.
"""

from __future__ import annotations
import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import anthropic

from tools import TOOL_REGISTRY, run_tool, ToolResult
import display


# ─────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    source_tool: str


@dataclass
class AgentState:
    target: str
    phase: str = "recon"
    iterations: int = 0
    max_iterations: int = 12
    tools_run: list[str] = field(default_factory=list)
    tool_results: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    open_ports: list[str] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    has_http: bool = False
    has_https: bool = False
    done: bool = False
    start_time: float = field(default_factory=time.time)


# ─────────────────────────────────────────────────────────────
# System prompt
# ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are PyKnock, an elite autonomous pentesting AI agent.
Your job is to methodically enumerate and analyse a target, run appropriate tools,
and surface real security findings — just like a senior penetration tester would.

## AVAILABLE TOOLS
{tools_list}

## YOUR TASK EACH TURN
1. Analyse all tool results accumulated so far.
2. Identify any security findings (real issues, misconfigs, open ports, weak certs, etc.).
3. Decide which tools to run NEXT (max 3 per turn).
4. Know when to STOP (no more useful tools to run, or max iterations reached).

## RESPONSE FORMAT — respond ONLY with valid JSON, no other text:
{{
  "analysis": "your expert analysis of results so far (2-5 sentences)",
  "findings": [
    {{
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "title": "short title",
      "detail": "specific technical detail about this finding"
    }}
  ],
  "next_tools": [
    {{
      "tool": "tool_name",
      "reason": "why this tool is useful now",
      "kwargs": {{}}
    }}
  ],
  "phase": "recon|enumeration|vulnerability|reporting",
  "done": false
}}

## RULES
- Be methodical: start with recon, move to enumeration, then vulnerability analysis.
- Never re-run a tool you already ran (check tools_run list).
- Only suggest tools relevant to what you've discovered (e.g. don't run ssl_check if port 443 isn't open).
- Findings must be concrete and specific — not vague.
- Set done=true when you have no more useful tools to run.
- Valid tool names: {tool_names}
"""


def _build_system_prompt() -> str:
    tool_lines = "\n".join(
        f"  - {name}: {info['desc']}" for name, info in TOOL_REGISTRY.items()
    )
    tool_names = ", ".join(TOOL_REGISTRY.keys())
    return SYSTEM_PROMPT.format(tools_list=tool_lines, tool_names=tool_names)


def _build_user_message(state: AgentState) -> str:
    """Construct the context message for this iteration."""
    lines = [
        f"TARGET: {state.target}",
        f"PHASE: {state.phase}",
        f"ITERATION: {state.iterations}/{state.max_iterations}",
        f"TOOLS RUN SO FAR: {', '.join(state.tools_run) or 'none'}",
        f"OPEN PORTS: {', '.join(state.open_ports) or 'unknown'}",
        "",
        "=== TOOL RESULTS ===",
    ]

    # Include last 8 results to stay within context limits
    recent = state.tool_results[-8:]
    for res in recent:
        lines.append(f"\n[{res['tool']}] (cmd: {res['command']})")
        output = res["stdout"] or res["stderr"] or "(no output)"
        # Truncate very long outputs
        if len(output) > 1500:
            output = output[:1500] + "\n... [truncated]"
        lines.append(output)
        if res.get("metadata"):
            lines.append(f"PARSED METADATA: {json.dumps(res['metadata'])}")

    lines.append("")
    lines.append("Based on the above, provide your JSON response.")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# Claude API call
# ─────────────────────────────────────────────────────────────

def _call_claude(client: anthropic.Anthropic, system: str, user_msg: str) -> dict:
    """Call Claude and return parsed JSON decision."""
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        system=system,
        messages=[{"role": "user", "content": user_msg}],
    )
    raw = response.content[0].text.strip()

    # Strip markdown code fences if present
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Attempt to salvage partial JSON
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if m:
            return json.loads(m.group(0))
        raise ValueError(f"Claude returned non-JSON:\n{raw[:400]}")


# ─────────────────────────────────────────────────────────────
# Execute tools decided by AI
# ─────────────────────────────────────────────────────────────

def _execute_tools(tool_decisions: list[dict], state: AgentState) -> None:
    for td in tool_decisions:
        tool_name = td.get("tool", "").strip()
        kwargs    = td.get("kwargs") or {}
        reason    = td.get("reason", "")

        if not tool_name or tool_name not in TOOL_REGISTRY:
            display.print_warn(f"Unknown tool requested: {tool_name!r}")
            continue
        if tool_name in state.tools_run:
            display.print_warn(f"Skipping already-run tool: {tool_name}")
            continue

        cmd_preview = f"{tool_name} {state.target}" + (f" {kwargs}" if kwargs else "")
        display.print_tool_start(tool_name, cmd_preview)
        display.print_info(f"Reason: {reason}")

        with display.spinner_context(f"Running {tool_name}…"):
            result: Optional[ToolResult] = run_tool(tool_name, state.target, **kwargs)

        if result is None:
            display.print_error(f"Tool {tool_name} returned no result")
            continue

        state.tools_run.append(tool_name)
        state.tool_results.append({
            "tool":     result.tool,
            "command":  result.command,
            "stdout":   result.stdout,
            "stderr":   result.stderr,
            "metadata": result.metadata,
            "success":  result.success,
        })

        display.print_tool_output(result.stdout or result.stderr)
        display.print_tool_done(tool_name, result.elapsed, len(result.metadata))

        # Update state from tool results
        if result.metadata.get("open_ports"):
            for p in result.metadata["open_ports"]:
                if p not in state.open_ports:
                    state.open_ports.append(p)
        if result.metadata.get("services"):
            state.services.extend(result.metadata["services"])
        for svc in state.services:
            if svc.get("port") == 80:
                state.has_http = True
            if svc.get("port") == 443:
                state.has_https = True


# ─────────────────────────────────────────────────────────────
# Main agent loop
# ─────────────────────────────────────────────────────────────

def run_agent(target: str, api_key: str, max_iterations: int = 12) -> AgentState:
    """Run the full autonomous pentesting loop. Returns final state."""
    client = anthropic.Anthropic(api_key=api_key)
    system_prompt = _build_system_prompt()
    state = AgentState(target=target, max_iterations=max_iterations)

    # ── Always start with basic recon ──────────────────────────
    display.print_phase("RECON", "Initial host discovery and information gathering")
    initial_tools = [
        {"tool": "ping",  "reason": "Check host reachability", "kwargs": {}},
        {"tool": "dns",   "reason": "Enumerate DNS records",   "kwargs": {}},
        {"tool": "whois", "reason": "Gather registrar/org info","kwargs": {}},
    ]
    _execute_tools(initial_tools, state)

    # ── Autonomous AI loop ─────────────────────────────────────
    while not state.done and state.iterations < state.max_iterations:
        state.iterations += 1
        display.print_rule(f"AI DECISION CYCLE {state.iterations}/{state.max_iterations}")

        with display.spinner_context("AI is analysing results…"):
            try:
                user_msg  = _build_user_message(state)
                decision  = _call_claude(client, system_prompt, user_msg)
            except Exception as e:
                display.print_error(f"Claude API error: {e}")
                break

        # Show AI analysis
        analysis = decision.get("analysis", "")
        if analysis:
            display.print_ai_thinking(analysis)

        # Record new findings
        raw_findings = decision.get("findings", [])
        for rf in raw_findings:
            sev = rf.get("severity", "INFO").upper()
            title  = rf.get("title", "")
            detail = rf.get("detail", "")
            if title and not any(f.title == title for f in state.findings):
                f = Finding(severity=sev, title=title, detail=detail,
                            source_tool=state.tools_run[-1] if state.tools_run else "AI")
                state.findings.append(f)
                display.print_finding(sev, title, detail)

        # Update phase
        new_phase = decision.get("phase", state.phase)
        if new_phase != state.phase:
            state.phase = new_phase
            display.print_phase(state.phase.upper(), f"Entering {state.phase} phase")

        # Check done flag
        if decision.get("done", False):
            state.done = True
            display.print_info("AI agent signalled completion.")
            break

        # Execute next tools
        next_tools = decision.get("next_tools", [])
        if not next_tools:
            display.print_info("No more tools to run.")
            state.done = True
            break

        display.print_ai_decision(
            analysis,
            [t.get("tool", "?") for t in next_tools],
        )
        _execute_tools(next_tools, state)

    # ── Final summary pass ──────────────────────────────────────
    if state.tool_results and not state.done:
        display.print_info("Running final AI analysis pass…")
        try:
            user_msg = _build_user_message(state)
            user_msg += "\n\nThis is the FINAL pass. Set done=true. Summarise all findings."
            decision = _call_claude(client, system_prompt, user_msg)
            for rf in decision.get("findings", []):
                title  = rf.get("title", "")
                if title and not any(f.title == title for f in state.findings):
                    state.findings.append(Finding(
                        severity=rf.get("severity", "INFO"),
                        title=title,
                        detail=rf.get("detail", ""),
                        source_tool="final_analysis",
                    ))
        except Exception:
            pass

    return state
