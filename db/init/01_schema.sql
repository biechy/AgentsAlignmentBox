-- AgentsAlignmentBox activity log. The proxy writes what the agents do; the monitor
-- writes flags; the web dashboard writes kill switches and flag reviews.
-- The agents cannot reach this database (separate Docker network + proxy blocklist).

CREATE SCHEMA IF NOT EXISTS obs;
SET search_path = obs, public;

-- One row per agent = one Messages API conversation. Every agent is treated the same
-- (orchestrator, sub-agent or one-off call); see proxy/identity.py for how requests are
-- assigned to agents.
CREATE TABLE agents (
    agent_id            TEXT PRIMARY KEY,
    session_id          TEXT,                      -- metadata.user_id / session header, if any
    parent_session_id   TEXT,                      -- Codex sub-agents: x-codex-parent-thread-id header
    client_ip           INET,
    client_host         TEXT,                      -- container name (reverse DNS on the Docker network)
    provider            TEXT,                      -- anthropic (Claude Code) | openai (Codex)
    model               TEXT,
    system_prompt_hash  TEXT,
    system_prompt       TEXT,
    first_prompt        TEXT,                      -- first user message = task given to the agent
    tools_offered       TEXT[],                    -- tool names declared in the request (empty: one-off call)
    running_tools_at_start JSONB,                  -- tool calls running in the same container when it started
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT now(),
    n_llm_calls         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX agents_session_idx ON agents(session_id);

-- One row per model call going through the proxy (Anthropic POST /v1/messages,
-- OpenAI POST /v1/responses or ChatGPT .../codex/responses).
CREATE TABLE llm_calls (
    call_id             UUID PRIMARY KEY,
    agent_id            TEXT NOT NULL REFERENCES agents(agent_id),
    provider            TEXT,                      -- anthropic | openai
    identified_by       TEXT,                      -- new_conversation | tool_chain | retry | first_message
    ts_request          TIMESTAMPTZ NOT NULL,
    ts_response         TIMESTAMPTZ,
    latency_ms          INTEGER,
    status_code         INTEGER,
    api_request_id      TEXT,                      -- `request-id` response header
    message_id          TEXT,
    model               TEXT,
    stream              BOOLEAN,
    n_messages          INTEGER,
    request_delta       JSONB,                     -- messages new since this agent's previous call
    response_content    JSONB,                     -- assembled content blocks (text, thinking, tool_use...)
    response_text       TEXT,
    thinking_text       TEXT,
    stop_reason         TEXT,
    input_tokens        INTEGER,
    output_tokens       INTEGER,
    cache_read_tokens   INTEGER,
    cache_write_tokens  INTEGER,
    error               TEXT
);
CREATE INDEX llm_calls_agent_ts_idx ON llm_calls(agent_id, ts_request);

-- One row per tool call decided by a model (client tools and server tools).
CREATE TABLE tool_calls (
    tool_use_id         TEXT PRIMARY KEY,
    agent_id            TEXT NOT NULL REFERENCES agents(agent_id),
    call_id             UUID REFERENCES llm_calls(call_id),
    ts                  TIMESTAMPTZ NOT NULL,      -- when the model emitted the call
    tool_name           TEXT NOT NULL,
    is_server_tool      BOOLEAN NOT NULL DEFAULT FALSE,  -- executed by the API (web_search...)
    tool_input          JSONB,
    ts_result           TIMESTAMPTZ,               -- when the result was sent back to the model
    result_content      TEXT,
    result_is_error     BOOLEAN
);
CREATE INDEX tool_calls_agent_ts_idx ON tool_calls(agent_id, ts);
CREATE INDEX tool_calls_name_idx     ON tool_calls(tool_name);

-- Every HTTP(S) request leaving the sandbox (sites visited, package installs, API calls...).
CREATE TABLE http_requests (
    id                  BIGSERIAL PRIMARY KEY,
    ts                  TIMESTAMPTZ NOT NULL,
    client_ip           INET,
    client_host         TEXT,
    method              TEXT,
    scheme              TEXT,
    host                TEXT,
    port                INTEGER,
    path                TEXT,
    url                 TEXT,
    user_agent          TEXT,
    req_content_type    TEXT,
    req_bytes           INTEGER,
    req_body_preview    TEXT,                      -- first bytes of the body (non-LLM requests)
    status_code         INTEGER,
    resp_content_type   TEXT,
    resp_bytes          INTEGER,
    duration_ms         INTEGER,
    is_llm_api          BOOLEAN NOT NULL DEFAULT FALSE,
    llm_call_id         UUID,                      -- set when is_llm_api
    agent_id            TEXT,                      -- agent that sent it; NULL when not conclusive
    tool_use_id         TEXT,                      -- running tool call that caused it, when known
    attribution         TEXT,                      -- LLM calls: identified_by; others: tool_tag | url_tag
                                                   -- | redirect | unknown_tag
                                                   -- | single_running_agent | content_match | ambiguous
                                                   -- | no_running_tool | none
    candidate_agent_ids TEXT[],                    -- agents that could have sent it
    proxy_tag           TEXT,                      -- tool call named in the proxy credentials, if any
    blocked             BOOLEAN NOT NULL DEFAULT FALSE,
    error               TEXT
);
CREATE INDEX http_requests_ts_idx    ON http_requests(ts);
CREATE INDEX http_requests_host_idx  ON http_requests(host);
CREATE INDEX http_requests_agent_idx ON http_requests(agent_id);

-- Connections that were not decrypted or not HTTP (TLS failures, raw TCP tunnels).
CREATE TABLE connections (
    id                  BIGSERIAL PRIMARY KEY,
    ts                  TIMESTAMPTZ NOT NULL,
    client_ip           INET,
    client_host         TEXT,
    host                TEXT,
    port                INTEGER,
    event               TEXT NOT NULL,             -- tls_failed | tcp_start | blocked_connect
    detail              TEXT
);

-- Written by the monitor (rules and model reviewer), reviewed in the web dashboard.
CREATE TABLE flags (
    id                  BIGSERIAL PRIMARY KEY,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    agent_id            TEXT REFERENCES agents(agent_id),
    severity            TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    category            TEXT,
    summary             TEXT NOT NULL,
    evidence            JSONB,                     -- ids of tool_calls / http_requests / llm_calls
    detector            TEXT,                      -- which monitor/rule produced it
    status              TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'dismissed', 'confirmed')),
    reviewed_by         TEXT,
    reviewed_at         TIMESTAMPTZ
);
CREATE INDEX flags_agent_idx ON flags(agent_id);

-- Kill switch. While a row exists, the proxy answers every model call of that agent
-- with a short "stopped by the operator" reply and refuses the requests of its tool
-- calls. Written by the web dashboard (and by the monitor when auto-kill is on);
-- deleting the row revives the agent.
CREATE TABLE agent_controls (
    agent_id            TEXT PRIMARY KEY REFERENCES agents(agent_id),
    action              TEXT NOT NULL DEFAULT 'kill' CHECK (action IN ('kill')),
    reason              TEXT,
    requested_by        TEXT,                      -- web | monitor
    ts                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Anomaly score of each finished tool call, from the monitor's tabular model (a
-- tabular foundation model on CPU, TabPFN, or a tree ensemble as fallback).
CREATE TABLE tabular_scores (
    tool_use_id         TEXT PRIMARY KEY REFERENCES tool_calls(tool_use_id),
    agent_id            TEXT REFERENCES agents(agent_id),
    ts                  TIMESTAMPTZ NOT NULL DEFAULT now(),   -- when it was scored
    score               REAL NOT NULL,             -- estimated probability that the call is a problem
    model               TEXT,                      -- tabpfn-v2 | extra-trees
    features            JSONB,                     -- the feature vector the model saw
    reasons             TEXT[]                     -- the suspicious features that were on
);
CREATE INDEX tabular_scores_agent_idx ON tabular_scores(agent_id);

-- One row per monitor cycle, so the dashboard can show whether the monitor is alive.
CREATE TABLE monitor_runs (
    id                  BIGSERIAL PRIMARY KEY,
    ts_start            TIMESTAMPTZ NOT NULL DEFAULT now(),
    ts_end              TIMESTAMPTZ,
    backend             TEXT,                      -- claude-code | api | rules-only
    model               TEXT,
    n_signals           INTEGER,
    n_rule_flags        INTEGER,
    n_model_flags       INTEGER,
    reviewed            BOOLEAN,                   -- the model reviewer ran this cycle
    tabular_model       TEXT,
    n_scored            INTEGER,                   -- tool calls scored by the tabular model
    n_tabular_alerts    INTEGER,                   -- of which above the threshold
    stopped             TEXT,
    summary             TEXT,
    error               TEXT
);

-- Everything that happened, in order, one row per event.
CREATE VIEW v_timeline AS
    SELECT c.ts_request AS ts, c.agent_id, 'llm_call' AS event,
           c.model AS what, left(c.response_text, 500) AS detail, c.call_id::text AS ref
      FROM llm_calls c
    UNION ALL
    SELECT t.ts, t.agent_id, CASE WHEN t.is_server_tool THEN 'server_tool' ELSE 'tool' END,
           t.tool_name, left(t.tool_input::text, 500), t.tool_use_id
      FROM tool_calls t
    UNION ALL
    SELECT h.ts, h.agent_id, CASE WHEN h.blocked THEN 'http_blocked' ELSE 'http' END,
           h.method || ' ' || h.host, left(h.url, 500), h.id::text
      FROM http_requests h WHERE NOT h.is_llm_api;

-- Agents with activity counters.
CREATE VIEW v_agents AS
    SELECT a.agent_id, a.client_host, a.session_id, a.provider, a.model,
           coalesce(cardinality(a.tools_offered), 0) > 0 AS has_tools,
           left(a.first_prompt, 300) AS task, a.first_seen, a.last_seen, a.n_llm_calls,
           (SELECT count(*) FROM tool_calls t WHERE t.agent_id = a.agent_id) AS n_tool_calls,
           (SELECT count(*) FROM http_requests h WHERE h.agent_id = a.agent_id AND NOT h.is_llm_api) AS n_http,
           (SELECT count(*) FROM flags f WHERE f.agent_id = a.agent_id AND f.status = 'open') AS n_open_flags,
           EXISTS (SELECT 1 FROM agent_controls k WHERE k.agent_id = a.agent_id) AS killed
      FROM agents a;

-- Distinct external hosts contacted, per container.
CREATE VIEW v_hosts AS
    SELECT client_host, host, count(*) AS n_requests, min(ts) AS first_ts, max(ts) AS last_ts,
           bool_or(blocked) AS any_blocked
      FROM http_requests
     WHERE NOT is_llm_api
     GROUP BY client_host, host;
