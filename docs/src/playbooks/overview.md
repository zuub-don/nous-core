# Playbooks

Playbooks are step-by-step workflows designed for AI agents operating through the MCP tool interface. Each playbook describes a concrete investigation or response pattern using the available tools.

## How to Use

Copy the relevant playbook into your agent's system prompt. The agent will follow the workflow using the MCP tools (`observe`, `query_events`, `query_entity`, `submit_verdict`, `submit_action`).

## Available Playbooks

| Playbook | Goal |
|----------|------|
| [Triage Alert Backlog](triage-alert-backlog.md) | Work through pending findings systematically |
| [Threat Hunt from IOC](threat-hunt-from-ioc.md) | Investigate blast radius from a known indicator |
| [Reduce Alert Fatigue](reduce-alert-fatigue.md) | Identify and suppress noisy, low-value alerts |
| [Investigate Entity](investigate-entity.md) | Deep-dive into a specific entity's activity and relationships |

## Design Principles

- **Tool-first** — every step maps to an MCP tool call
- **Iterative** — workflows loop through observe → query → assess → act
- **Explainable** — agents provide reasoning with every verdict and action
