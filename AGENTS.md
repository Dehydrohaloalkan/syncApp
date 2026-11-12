# SyncApp repository instructions

For substantive development in this repository, read and apply the locally installed skill [syncapp-development](/home/alex/.codex/skills/syncapp-development/SKILL.md). Its source of truth is the installed SKILL.md; this file keeps the requested workflow discoverable in future sessions.

Use three agents: coder on `gpt-6-luna`, tester on `gpt-6-luna`, independent reviewer on `gpt-6.1-sol`. The primary agent coordinates assignments, updates the plan, integrates findings and verifies completion. Model overrides require `fork_turns="none"`. If a model is unavailable, explain the closest substitute. Questions and trivial documentation-only edits can be handled directly.

Give agents disjoint file ownership. Normally coder owns `SyncApp/**`, tester owns `tests/**` and `docs/TESTING.md`, reviewer owns `docs/REVIEW.md`, coordinator owns plan and other documentation. Keep production fixes with coder while tester/reviewer report concrete failures. Coordinate builds that share outputs.

Read `PLAN.md` for the current product requirements. Transfer is one-way: Personal publishes signed encrypted commit changes to GitHub/junk; Work only pulls, decrypts and applies, with no transport commit/push or outgoing receipts. The user prepares the initial matching code copy separately; the public Work key may be copied manually as text to Personal. All source code and metadata are encrypted `.age` packages. Public bootstrap identifiers/keys can remain in `project.json`; secrets and source metadata cannot. No QR or reverse channel. Source commits on Work are created manually after applying packages. Personal publication must not wait for Work acknowledgements.

Run meaningful integration, HTTP and browser checks using temporary repositories and a local bare remote. Never infer Windows/WSL validation from Linux results. Do not commit, push or publish to a real remote unless requested. Preserve unrelated existing work.
