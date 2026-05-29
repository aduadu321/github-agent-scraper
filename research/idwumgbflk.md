# Agent Handoff Best Practices — Research Findings
*Research date: 2026-05-26 | Model: claude-sonnet-4-6*

## Sources consulted
- OpenAI Agents SDK — Handoffs documentation
- akitaonrails/ai-memory — cross-agent handoff via git-backed wiki
- LessonL framework (arXiv 2505.23946) — multi-agent error learning
- Aegis (arXiv 2509.14295) — error attribution in multi-agent systems
- Reflexion — reflection + lesson storage
- mem0.ai — memory architecture for LLM agents
- Contextual Memory Virtualisation (arXiv 2602.22402) — DAG-based state
- Multi-Layered Memory Architectures (arXiv 2603.29194)

---

## Pattern 1 — Compile, don't retrieve

**What:** Instead of logging raw session transcripts and querying them later, consolidate observations into coherent narrative pages at session end.

**Why:** Raw logs grow unbounded; LLM context windows overflow. Compiled summaries are stable, searchable, and fast to prepend.

**How:** At session-end hook: read task_log.json → call handoff_gen.py → overwrite HANDOFF.md with structured block. The previous blocks remain as append-only history.

**Our implementation:** `handoff_gen.py --auto` does exactly this.

---

## Pattern 2 — Negative lessons are essential

**Finding (LessonL paper):** Agents given only positive lessons ("do this") performed worse than agents given mixed positive + negative lessons. Failure-based lessons prevent repeat mistakes across agents.

**Format that works:**
```
NEVER DO: <specific prohibited action>
WHY:      <concrete consequence>
ALWAYS DO: <the correct alternative>
```

**Our implementation:** `mistake_db.py` stores `never_do` + `always_do` as separate columns. HANDOFF.md blocks have explicit `### 🚫 NEVER DO AGAIN` and `### ✅ ALWAYS DO` sections.

---

## Pattern 3 — Typed handoff context (structured schema)

**Finding (OpenAI Agents SDK):** Handoffs represented as tool calls with explicit schemas. Receiving agent gets `HandoffInputData` with: `input_history`, `pre_handoff_items`, `new_items`. Untyped free-text handoffs cause agents to miss critical constraints.

**Key fields for code agents:**
- Task description
- Files touched (with action: created/modified/deleted)
- Errors encountered + fixes applied
- Rules extracted (never/always)
- Next steps (numbered, actionable)
- Blockers (explicit, not buried in prose)

**Our implementation:** `build_handoff_block()` in `handoff_gen.py` enforces this schema. `task_logger.py` lets agents write to it during execution.

---

## Pattern 4 — Lesson bank with performance scoring

**Finding (LessonL):** Storing lessons as `(content, speedup_score, effectiveness_factor)` tuples and selecting top-k by score + semantic similarity outperforms static lesson lists.

**Practical adaptation:** In `mistake_db.py`, the `severity` field (CRITICAL/HIGH/MEDIUM/LOW) acts as the score. `--search` queries use SQLite FTS for semantic-ish retrieval. Future improvement: add embedding-based retrieval.

**Actionable pattern:**
- Pre-populate DB with known mistakes at system init (done: 16 seed records).
- Add new entries after every task with errors.
- Query before starting a task in a domain: `python mistake_db.py --agent github-hunter --all`.

---

## Pattern 5 — Git-backed history with "where you left off"

**Finding (akitaonrails/ai-memory):** Storing memory in a markdown wiki tracked by git enables:
- Time-travel: `git log` shows what each agent knew at each point.
- Cross-vendor handoff: any agent (Claude, GPT, Gemini) reads same markdown.
- Natural-language query: "Where did we leave off?" resolves to last HANDOFF.md block.

**Our implementation:** HANDOFF.md uses append-only blocks separated by `---`. Each block is self-contained (agent, task, timestamp, outcome). Git history provides version control.

**Key rule:** Prepend HANDOFF.md content at session start so agent sees "where we left off" immediately.

---

## Pattern 6 — Autonomy levels for error handling

**Finding (Trackmind AI Handoff Protocols):** Not all errors should trigger the same response. Four levels:
1. **Level 1 — Fully supervised:** Human approves before agent acts.
2. **Level 2 — Conditional autonomy:** Agent acts within bounds; exceptions escalate.
3. **Level 3 — Monitored autonomy:** Agent acts freely; logs everything for review.
4. **Level 4 — Full autonomy:** Agent acts and self-corrects; escalates only on critical failure.

**Applied to our agents:**
- Rate limit errors → Level 3: auto-sleep, log, continue.
- Auth errors → Level 2: pause, report, wait for token fix.
- Logic bugs → Level 3: log to mistake_db, mark finding as LIKELY_FP, continue.
- Credential exposure risk → Level 1: STOP, alert user.

---

## Pattern 7 — Contextual Memory Virtualisation (DAG state)

**Finding (arXiv 2602.22402):** Treat accumulated context as version-controlled state. Operations: COMMIT (checkpoint), BRANCH (explore alternative), MERGE (combine findings), TRIM (reduce context).

**Practical adaptation for our system:**
- Each `log_done()` call = COMMIT.
- `task_log.json` = working memory within session.
- `HANDOFF.md` block = compiled commit artifact.
- `mistake_db.sqlite` = long-term semantic memory (cross-session, cross-agent).

---

## Pattern 8 — Multi-layered memory architecture

**Finding (arXiv 2603.29194):** Three layers work best:
1. **Working memory** (in-session): task_log.json.
2. **Episodic memory** (per-task): HANDOFF.md blocks.
3. **Semantic memory** (cross-task, cross-agent): mistake_db.sqlite.

Each layer has different write frequency and read cost:
- Working: written every few seconds, read at task end.
- Episodic: written at task end, read at session start.
- Semantic: written on error/lesson, read before task start in a domain.

---

## Pattern 9 — Error attribution before lesson generation

**Finding (Aegis, arXiv 2509.14295):** In multi-agent systems, 17x error amplification occurs when mistakes aren't attributed to specific agents/components. The ECHO approach: hierarchical context + decoupled analysis + confidence-weighted consensus.

**Applied:** `mistake_db.py` requires `--agent` and `--type` fields for every entry. This enables filtering: "which agent made rate_limit mistakes?" and "which mistakes are CRITICAL across all agents?"

---

## Pattern 10 — Reflexion: store lessons as first-class memory

**Finding (Reflexion):** Agents that reflect on feedback and store structured lessons in memory improve on subsequent attempts without weight updates. Key: lessons must be stored in a retrievable format, not just in the prompt.

**Our implementation:**
- `task_logger.log_lesson()` writes during execution.
- `handoff_gen.py` extracts and formats into HANDOFF.md.
- `mistake_db.py` persists permanently in SQLite.
- Before a new task: query mistake_db → prepend relevant rules to system prompt.

**Recommended workflow:**
```
# Before starting a domain task:
python C:\Users\aduad\tools\agent-leveling\mistake_db.py --agent github-hunter --all
# Paste output into agent system prompt as "Known constraints"
```

---

## Adoption priorities (what to do first)

1. **Highest ROI:** Pre-populate `mistake_db.sqlite` and query it before every hunt.  
   Command: `python mistake_db.py --agent github-hunter --all`

2. **Second:** Import `task_logger` in every agent script — 3 lines of code, captures all errors automatically.

3. **Third:** Run `handoff_gen.py --auto` after every task — generates structured HANDOFF.md with no manual effort.

4. **Fourth:** Wire `auto_handoff.ps1` into the Stop hook in settings.json for fully automatic operation.

5. **Future:** Add embedding-based retrieval to mistake_db for semantic search across large lesson banks.
