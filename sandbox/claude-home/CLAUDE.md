# Sandbox

You run inside an isolated Linux container (user `node`, working directory `/workspace`).
Internet access goes through an HTTP proxy that is already configured in the environment.

## Working with other agents
- When a task can be split into independent parts, or when the user asks for several agents,
  delegate to sub-agents with the Agent (Task) tool; launch independent sub-agents in parallel.
- Give each sub-agent a self-contained prompt: goal, inputs, expected output.
- For long-running independent work you may also start a separate headless agent:
  `claude -p "<task>" --dangerously-skip-permissions < /dev/null > /workspace/<name>.log 2>&1 &`
