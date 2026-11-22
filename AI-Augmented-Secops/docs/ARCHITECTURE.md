# secops-triage-guard: Technical Architecture and Data Flow Diagrams

This document describes the implemented system. File paths refer to this repository.

## 1. Design principle

The LLM is an untrusted component. It can only emit SQL text and answer text. Everything it receives and everything it emits passes through deterministic, non-LLM controls (input guard, SQL validator, read-only database, masker, audit log). Every control fails closed.

## 2. Technical architecture

### 2.1 Deployment view (Docker Compose)

```mermaid
flowchart LR
    Analyst["Analyst browser"]
    subgraph Host["Docker host - ports bound to 127.0.0.1"]
        subgraph DashC["dashboard container"]
            UI["Streamlit UI<br/>src/app.py"]
        end
        subgraph ApiC["api container - non-root"]
            API["FastAPI<br/>src/api.py"]
            Agent["Triage_Agent<br/>src/engine/triage_agent.py"]
        end
        subgraph OllC["ollama container"]
            LLM["Ollama<br/>llama3.2 or mistral"]
        end
        V1[("volume findings_db<br/>DuckDB file")]
        V2[("volume runbook_store<br/>ChromaDB files")]
        V3[("volume audit_log<br/>audit_logs.jsonl + .head")]
        V4[("volume ollama_models")]
    end
    Analyst -->|"HTTP 8501"| UI
    UI -->|"HTTP 8000 - X-User-Role, X-API-Key"| API
    API --> Agent
    Agent -->|"HTTP 11434"| LLM
    Agent -->|"read-only"| V1
    Agent -->|"query"| V2
    API -->|"append + verify"| V3
    LLM --- V4
```

### 2.2 Component view

```mermaid
flowchart TB
    subgraph Presentation
        UI["Dashboard<br/>src/app.py<br/>ApiClient via httpx"]
    end
    subgraph Interface
        API["API<br/>src/api.py<br/>validation, API key, role header,<br/>rate limiter, generic errors"]
    end
    subgraph Orchestration
        Agent["Triage_Agent<br/>explicit sequential steps,<br/>Pydantic models"]
        LLMC["LLM client<br/>src/engine/llm_client.py<br/>generate_sql, generate_answer only"]
    end
    subgraph Guardrails["Deterministic guardrails - src/guardrails"]
        IG["Input_Guard<br/>input_guard.py"]
        SV["SQL_Validator<br/>sql_validator.py<br/>sqlglot AST"]
        PM["PII_Masker<br/>pii_masker.py<br/>Presidio + regex"]
    end
    subgraph Data["Data layer - src/engine"]
        DB["FindingsDB<br/>db.py<br/>read-only DuckDB"]
        RS["RunbookStore<br/>runbook_store.py<br/>ChromaDB + MiniLM"]
    end
    subgraph AuditL["Audit - src/audit"]
        AL["Audit_Logger<br/>logger.py<br/>hash chain"]
    end
    CFG["Config and policy<br/>src/config.py<br/>ALLOWLISTED_SCHEMA, ROLE_POLICY"]
    MOD["Shared Pydantic models<br/>src/models.py"]
    SEED["Seed_Generator<br/>data/seed_findings.py"]

    UI --> API
    API --> Agent
    Agent --> IG
    Agent --> LLMC
    Agent --> SV
    Agent --> DB
    Agent --> PM
    Agent --> RS
    Agent --> AL
    AL --> PM
    API --> AL
    SV --> CFG
    Agent --> CFG
    SEED --> DB
    SEED --> RS
    Agent -.-> MOD
    API -.-> MOD
```

### 2.3 Component responsibilities

| Component | File | Responsibility |
|---|---|---|
| Dashboard | `src/app.py` | Chat, SQL view, masked-vs-blocked telemetry, audit viewer. Talks only to the API. |
| API | `src/api.py` | `POST /triage`, `GET /audit`, `GET /audit/verify`, `GET /health`. Pydantic validation, 30 req/min rate limit, optional `X-API-Key`, `X-User-Role` check, generic 500s. |
| Triage_Agent | `src/engine/triage_agent.py` | Runs the ten-step pipeline and writes exactly one audit record per request. |
| LLM client | `src/engine/llm_client.py` | LangChain `ChatOllama`, no tools, 60 s limit, errors become `LLMUnavailable`. |
| Input_Guard | `src/guardrails/input_guard.py` | Normalizes prompts, blocks injection, exfiltration, write intent, jailbreaks. Scrubs retrieved text. |
| SQL_Validator | `src/guardrails/sql_validator.py` | Single SELECT only, allowlisted tables and columns, no file or catalog access, LIMIT clamp. |
| PII_Masker | `src/guardrails/pii_masker.py` | Presidio plus regex rules, typed `[REDACTED:TYPE]` placeholders, idempotent. |
| FindingsDB | `src/engine/db.py` | Read-only DuckDB connection with external access disabled, 10 s timeout, approval token, sanitized errors. |
| RunbookStore | `src/engine/runbook_store.py` | File-backed ChromaDB, all-MiniLM-L6-v2 embeddings, top-k retrieval. |
| Audit_Logger | `src/audit/logger.py` | Append-only JSONL, SHA-256 hash chain, `.head` anchor, locked writes, masked fields. |
| Config | `src/config.py` | Environment settings, the single allowlisted schema, role policy. |
| Seed_Generator | `data/seed_findings.py` | Deterministic synthetic findings with fake PII, secrets and injection payloads. Loads the DB and runbook store. |

### 2.4 Request sequence

```mermaid
sequenceDiagram
    autonumber
    actor A as Analyst
    participant UI as Dashboard
    participant API as FastAPI
    participant AG as Triage_Agent
    participant IG as Input_Guard
    participant L as Ollama LLM
    participant SV as SQL_Validator
    participant DB as FindingsDB
    participant PM as PII_Masker
    participant RS as RunbookStore
    participant AL as Audit_Logger

    A->>UI: question and role
    UI->>API: POST /triage
    API->>API: validate body, rate limit
    API->>AG: TriageRequest
    AG->>IG: check_prompt
    alt blocked
        IG-->>AG: blocked with reason
    else allowed
        AG->>L: schema description and prompt
        L-->>AG: SQL text
        AG->>SV: validate_sql
        opt blocked, one retry only
            SV-->>AG: reason code
            AG->>L: reason as feedback
            L-->>AG: new SQL text
            AG->>SV: validate_sql
        end
        SV-->>AG: validated SQL
        AG->>DB: execute_readonly with approval token
        DB-->>AG: rows
        AG->>PM: mask rows
        AG->>IG: scrub_retrieved
        AG->>RS: query top 3
        RS-->>AG: passages
        AG->>IG: scrub_retrieved
        AG->>PM: mask passages
        AG->>L: masked rows and passages
        L-->>AG: answer text
        AG->>PM: mask answer
    end
    AG->>AL: append one record
    alt audit write fails
        AL-->>AG: error
        AG-->>API: audit_failure, no data
    else written
        AG-->>API: response or block
    end
    API-->>UI: 200, 400 or typed error
    UI-->>A: masked data only
```

### 2.5 Technology stack

| Concern | Choice |
|---|---|
| Language | Python 3.11+ |
| LLM | Ollama, llama3.2 or mistral (set by `LLM_MODEL`), via `langchain-ollama` |
| Database | DuckDB, opened read-only |
| Vector store | ChromaDB with sentence-transformers all-MiniLM-L6-v2 |
| SQL guardrail | sqlglot AST parsing |
| Masking | Microsoft Presidio (analyzer and anonymizer) plus regex |
| API and UI | FastAPI, Streamlit |
| Validation | Pydantic, pydantic-settings |
| Tests | pytest, Hypothesis |
| Packaging | Docker, Docker Compose |

## 3. Data flow diagrams

Notation: rectangles are external entities, rounded boxes are processes, cylinders are data stores. Dashed boxes are trust boundaries.

### 3.1 Level 0: context diagram

```mermaid
flowchart LR
    Analyst["External entity:<br/>Analyst, Admin, Viewer"]
    Ollama["External entity:<br/>Local Ollama LLM"]
    Admin["External entity:<br/>Operator or seeder run"]
    P0(("0<br/>secops-triage-guard"))

    Analyst -->|"natural-language question, role, API key"| P0
    P0 -->|"masked answer, validated SQL, masked rows, cited runbooks, or block reason"| Analyst
    P0 -->|"schema description, masked context"| Ollama
    Ollama -->|"SQL text, answer text"| P0
    Admin -->|"seed command, config env vars"| P0
```

### 3.2 Level 1: main processes and data stores

```mermaid
flowchart TB
    Analyst["Analyst / Admin / Viewer"]
    LLM["Ollama LLM<br/>untrusted"]

    P1("1.0 Receive and validate request<br/>API")
    P2("2.0 Screen prompt<br/>Input_Guard")
    P3("3.0 Generate SQL<br/>Triage_Agent + LLM")
    P4("4.0 Validate SQL<br/>SQL_Validator")
    P5("5.0 Execute query<br/>FindingsDB read-only")
    P6("6.0 Mask and scrub results<br/>PII_Masker + Input_Guard")
    P7("7.0 Retrieve runbooks<br/>RunbookStore")
    P8("8.0 Generate answer<br/>Triage_Agent + LLM")
    P9("9.0 Record audit<br/>Audit_Logger")

    D1[("D1 Findings DB<br/>DuckDB")]
    D2[("D2 Runbook store<br/>ChromaDB")]
    D3[("D3 Audit log<br/>audit_logs.jsonl")]
    D4[("D4 Policy config<br/>allowlist, role policy")]

    Analyst -->|"prompt, role"| P1
    P1 -->|"TriageRequest"| P2
    P2 -->|"normalized prompt"| P3
    P2 -.->|"blocked + reason"| P9
    D4 -->|"role-restricted schema"| P3
    P3 -->|"schema + prompt"| LLM
    LLM -->|"SQL text"| P3
    P3 -->|"candidate SQL"| P4
    D4 -->|"allowlisted schema"| P4
    P4 -->|"validated SQL + approval token"| P5
    P4 -.->|"blocked reason, one retry"| P3
    P4 -.->|"blocked + reason"| P9
    D1 -->|"raw rows"| P5
    P5 -->|"raw rows"| P6
    P6 -->|"masked, scrubbed rows"| P7
    P7 -->|"query text"| D2
    D2 -->|"raw passages"| P7
    P7 -->|"passages"| P6
    P6 -->|"masked rows + masked passages"| P8
    P8 -->|"context"| LLM
    LLM -->|"answer text"| P8
    P8 -->|"answer"| P6
    P6 -->|"masked answer + summary"| P9
    P9 -->|"hash-chained record"| D3
    P9 -->|"response or audit_failure"| P1
    P1 -->|"masked response or typed error"| Analyst
```

### 3.3 Level 1 with trust boundaries

```mermaid
flowchart LR
    subgraph TB0["TB0 Untrusted: client side"]
        Analyst["Analyst browser"]
    end
    subgraph TB1["TB1 Presentation"]
        UI["Dashboard"]
    end
    subgraph TB2["TB2 Trusted enforcement core"]
        API["API"]
        IG["Input_Guard"]
        SV["SQL_Validator"]
        PM["PII_Masker"]
        AG["Triage_Agent"]
        AL["Audit_Logger"]
    end
    subgraph TB3["TB3 Untrusted: model"]
        LLM["Ollama LLM"]
    end
    subgraph TB4["TB4 Data stores"]
        DB[("Findings DB<br/>read-only")]
        RS[("Runbook store")]
        LOG[("Audit log")]
    end

    Analyst -->|"1 prompt - untrusted input"| UI
    UI -->|"2 HTTP + role header"| API
    API --> AG
    AG --> IG
    AG -->|"3 prompt only after guard"| LLM
    LLM -->|"4 SQL text - untrusted output"| SV
    SV -->|"5 approved SQL only"| DB
    DB -->|"6 untrusted row text - may hold injection or PII"| PM
    RS -->|"7 untrusted passages"| PM
    PM -->|"8 masked, scrubbed context"| LLM
    LLM -->|"9 answer text"| PM
    AG --> AL
    AL --> LOG
    AG -->|"10 masked response"| API
```

Boundary crossings and the control applied at each:

| # | Crossing | Control |
|---|---|---|
| 1, 2 | Browser to UI to API | Pydantic validation, rate limit, API key, role header |
| 3 | Prompt into LLM | Input_Guard normalization and pattern blocks |
| 4 | LLM output into database path | sqlglot validation, allowlist, single SELECT, LIMIT clamp |
| 5 | SQL into database | Read-only connection, external access off, approval token, 10 s timeout |
| 6, 7 | Stored text into LLM context | Masking, injection scrubbing, `<data>` tag stripping |
| 8, 9 | Context to and from LLM | LLM has no tools, answer is masked again |
| 10 | Response to caller | Masked data only, generic errors |

### 3.4 Level 2: sensitive-data flow (masking)

This shows where each class of sensitive value can appear and where it is removed.

```mermaid
flowchart LR
    SRC1["Findings rows<br/>emails, hostnames, account IDs,<br/>tokens, IPs, injection text"]
    SRC2["Runbook passages"]
    SRC3["User prompt"]
    SRC4["LLM answer"]

    M1("Mask rows")
    S1("Scrub injection<br/>from row text")
    M2("Mask passages")
    S2("Scrub injection<br/>from passages")
    M3("Mask prompt copy<br/>for answer context")
    M4("Mask answer")
    M5("Mask audit fields")

    CTX["LLM answer context<br/>masked + scrubbed only"]
    OUT["API response and UI"]
    LOG[("Audit log<br/>masked, counts only")]

    SRC1 --> M1 --> S1 --> CTX
    SRC2 --> S2 --> M2 --> CTX
    SRC3 --> M3 --> CTX
    CTX --> LLMn(("LLM"))
    LLMn --> SRC4 --> M4 --> OUT
    S1 --> OUT
    SRC3 --> M5
    SRC4 --> M5
    M5 --> LOG
```

### 3.5 Level 2: audit log flow

```mermaid
flowchart TB
    E["AuditEntry from Triage_Agent<br/>prompt, SQL, decisions,<br/>outcome, latency, role"]
    A1("Mask free-text fields")
    A2("Acquire thread lock and flock")
    A3("Read last line, compute SHA-256 prev_hash")
    A4("Append one JSON line, fsync")
    A5("Update .head anchor<br/>hash and count, best effort")
    F[("audit_logs.jsonl")]
    H[("audit_logs.jsonl.head")]
    V("Verify<br/>recompute chain, compare anchor")
    R["GET /audit/verify result:<br/>valid or first invalid line"]
    ERR["AuditWriteError<br/>response withheld: audit_failure"]

    E --> A1 --> A2 --> A3 --> A4 --> F
    A4 --> A5 --> H
    A3 -.->|"cannot read log"| ERR
    A4 -.->|"write fails"| ERR
    F --> V
    H --> V
    V --> R
```

### 3.6 Level 2: seeding flow

```mermaid
flowchart LR
    OP["Operator or container entrypoint<br/>seed_findings.py --only-missing"]
    G("Generate findings<br/>seeded RNG, deterministic")
    DBB("Build DuckDB in temp file")
    CH("Chunk runbooks")
    EM("Embed with MiniLM<br/>or fake embedding in tests")
    RSB("Build new Chroma store in temp dir")
    SW("Atomic swap")
    D1[("Findings DB")]
    D2[("Runbook store")]
    RB["data/runbooks/*.md"]

    OP --> G --> DBB --> SW
    RB --> CH --> EM --> RSB --> SW
    SW --> D1
    SW --> D2
    SW -.->|"failure: old data kept, exit non-zero"| OP
```

## 4. Data dictionary

| Data item | Produced by | Consumed by | Sensitivity | Where it may be stored |
|---|---|---|---|---|
| User prompt | Analyst | Input_Guard, LLM (normalized), audit (masked) | Untrusted input | Audit log, masked only |
| Candidate SQL | LLM | SQL_Validator | Untrusted output | Audit log, masked |
| Validated SQL and approval token | SQL_Validator | FindingsDB | Trusted, derived | Audit log |
| Raw result rows | FindingsDB | PII_Masker only | Contains synthetic PII and secrets | Memory only |
| Masked rows | PII_Masker | LLM context, API response | Masked | Response |
| Runbook passages | RunbookStore | Input_Guard, PII_Masker | Untrusted text | Memory only |
| Masking summary | PII_Masker | Audit, API response | Counts per type, no values | Audit log |
| Audit record | Audit_Logger | Verify, `/audit`, dashboard | Masked, hash-chained | `audit_logs.jsonl` |

## 5. Failure behaviour

| Failure | Result |
|---|---|
| Prompt blocked by Input_Guard | HTTP 400, no LLM call, one audit record |
| SQL blocked twice | HTTP 400 with the second reason code, nothing executed |
| LLM returns no or multiple statements | `invalid_llm_output`, nothing executed |
| LLM unreachable or over 60 s | `llm_unavailable`, no partial data |
| Query over 10 s | `query_timeout`, no rows |
| Database error | Generic error, error class in the audit record |
| Presidio fails | Regex rules only, `degraded_mode` set |
| Regex layer fails | Value replaced by `[REDACTED:MASKING_FAILURE]` |
| Audit write fails | Response withheld, `audit_failure` |
| Unhandled exception | HTTP 500, generic body with request ID |

## 6. Known limits

- The `X-User-Role` header and the `role` field in the `/triage` body are self-asserted. Viewer isolation only constrains honest clients unless a gateway authenticates users.
- The `.head` anchor is best effort. An attacker who can rewrite both files can forge a consistent log.
- The rate limiter is in-process and keyed by client IP.
- Presidio produces false positives (over-masking) and the regex rules have bounded coverage.
- Docker packaging and live Ollama runs have not been exercised in this environment.
