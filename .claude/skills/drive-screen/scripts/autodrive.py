#!/usr/bin/env python3
"""
Run a driven Claude Code session to the end of a turn, answering its permission
prompts, and stop the moment anything looks like it needs a human.

This answers prompts inside the DRIVEN SESSION'S OWN terminal UI. It has nothing
to do with operating-system dialogs and cannot answer one: every keystroke it
sends goes to the editor window you name.

What it does differently from a naive approval loop
---------------------------------------------------
The obvious version watches for the driven session to go quiet and assumes
silence means a prompt is waiting. Silence does not mean that. A finished turn
and a waiting prompt are identical from outside, so that version answers prompts
that are not there, and types into a session that has already stopped.

This one reads the transcript instead. A session waiting at a prompt has a
tool_use with no matching tool_result; a finished one does not. So before every
approval it knows there IS a prompt, and it knows exactly which command is behind
it, which is what makes the run auditable rather than a click-through.

It also presses Enter rather than typing a digit. Enter accepts the highlighted
option, which is approve-once. Typing "2" selects the variant that stops asking,
and for a Bash command that writes a permanent rule into the repository's
settings, unattended, which is not a thing to do while nobody is watching.

  autodrive.py --title "<window>" --repo <path> [--session <uuid>]
               [--max 25] [--timeout 900] [--idle 45]
               [--shot-dir <dir>] [--dry-run]

Exit codes
  0  the turn completed
  1  timed out with the agent still working
  2  approvals are not reaching the session, or the cap was hit
  3  stopped deliberately for a human: a command matched the refuse list,
     or --dry-run
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import session_watch as sw  # noqa: E402

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", newline="\n")
    except Exception:
        pass


# Commands this will never approve on its own. The point is not to be a security
# boundary, because a determined mistake can be spelled around any regex. The
# point is that the class of thing you most regret approving while away is small,
# well known, and cheap to stop on. Anything matching hands control back with the
# command printed, and you approve it yourself or you do not.
REFUSE = [
    (r"\brm\s+(-\w*\s+)*-\w*[rf]", "recursive or forced delete"),
    (r"\brmdir\s+/s", "recursive delete"),
    (r"\bgit\s+push\b.*(--force|-f)\b", "force push"),
    (r"\bgit\s+reset\s+--hard\b", "discards working tree"),
    (r"\bgit\s+clean\b.*-\w*[fdx]", "deletes untracked files"),
    (r"\bsudo\b", "privilege escalation"),
    (r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^|]*\|\s*(sudo\s+)?(ba|z|)sh",
     "pipes the network into a shell"),
    (r"\bdd\s+if=", "raw disk write"),
    (r"\b(mkfs|diskpart|format)\b", "formats a volume"),
    (r"\b(shutdown|reboot|Restart-Computer|Stop-Computer)\b", "restarts the machine"),
    (r"\b(npm|pnpm|yarn)\s+publish\b", "publishes a package"),
    (r"\bgh\s+release\s+create\b", "publishes a release"),
    (r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", "destructive SQL"),
    (r"\bDELETE\s+FROM\b(?!.*\bWHERE\b)", "unfiltered DELETE"),
    (r"\btruncate\b", "truncates data"),
    (r"\bkill(all)?\b|\btaskkill\b|\bStop-Process\b", "kills processes"),
    (r"\bchmod\s+(-R\s+)?777\b", "world-writable permissions"),
    (r"\b(Remove-Item|del)\b.*-Recurse", "recursive delete"),
]

# These never carry a destructive command, so they are approved without matching.
SAFE_TOOLS = {"Read", "Grep", "Glob", "NotebookRead", "TodoWrite"}


def refuses(tool: str, detail: str) -> str | None:
    if tool in SAFE_TOOLS:
        return None
    for pattern, why in REFUSE:
        if re.search(pattern, detail, re.IGNORECASE):
            return why
    return None


def screenctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, os.path.join(HERE, "screenctl.py"), *args],
                          capture_output=True, text=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--title", required=True, help="window holding the driven session")
    ap.add_argument("--repo", required=True, help="repo the driven session runs in")
    ap.add_argument("--session", default=None, help="pin one session uuid (prefix ok)")
    ap.add_argument("--max", type=int, default=25, help="approval cap")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--idle", type=int, default=45)
    ap.add_argument("--poll", type=float, default=3.0)
    ap.add_argument("--shot-dir", default=None,
                    help="screenshot before every approval, into this directory")
    ap.add_argument("--dry-run", action="store_true",
                    help="report the first prompt and what it would do, approve nothing")
    a = ap.parse_args()

    sw.PIN = a.session
    path = sw.latest(a.repo)
    base_turns = len(sw.turn_ends(sw.records(path)))
    print(f"Driving {path.name} in {a.title!r} (baseline {base_turns} turns, "
          f"cap {a.max} approvals)")
    if a.dry_run:
        print("DRY RUN: nothing will be sent.")

    approvals = 0
    last_count = len(sw.records(path))
    last_change = time.time()
    deadline = time.time() + a.timeout

    while time.time() < deadline:
        path = sw.latest(a.repo)
        recs = sw.records(path)

        if len(sw.turn_ends(recs)) > base_turns:
            print(f"TURN_COMPLETE after {approvals} approval(s)")
            if texts := sw.assistant_texts(recs):
                print("\n--- final assistant message ---")
                print(texts[-1][:2000])
            return 0

        if len(recs) != last_count:
            last_count = len(recs)
            last_change = time.time()
            time.sleep(a.poll)
            continue

        if time.time() - last_change < a.idle:
            time.sleep(a.poll)
            continue

        pending = sw.pending_tool_details(recs)
        if not pending:
            # Quiet with nothing outstanding is a finished turn that never wrote a
            # completion record. Answering here is exactly the old bug.
            print(f"TURN_COMPLETE (quiet, nothing outstanding) after {approvals} approval(s)")
            if texts := sw.assistant_texts(recs):
                print("\n--- final assistant message ---")
                print(texts[-1][:2000])
            return 0

        if approvals >= a.max:
            print(f"CAP: {a.max} approvals reached. Stopping deliberately.")
            return 2

        print(f"\n--- prompt {approvals + 1} (records {len(recs)}) ---")
        for tool, detail in pending:
            print(f"    {tool}: {detail[:400] or '(no command recorded)'}")

        for tool, detail in pending:
            if why := refuses(tool, detail):
                print(f"\nREFUSING to auto-approve: {why}.")
                print(f"    {tool}: {detail[:400]}")
                print("Answer this one yourself. Nothing was sent.")
                return 3

        if a.shot_dir:
            os.makedirs(a.shot_dir, exist_ok=True)
            shot = os.path.join(a.shot_dir, f"prompt-{approvals + 1:02d}.png")
            screenctl("shot", "--title", a.title, "--out", shot)
            print(f"    screenshot: {shot}")

        if a.dry_run:
            print("\nDRY RUN: would press Enter to approve. Stopping here.")
            return 3

        # Enter, not a digit: it accepts the highlighted option, which is
        # approve-once. screenctl verifies the foreground window by identity and
        # exits non-zero rather than sending, so a stolen focus stops the run
        # instead of typing an approval into whatever is actually in front.
        r = screenctl("key", "--title", a.title, "--keys", "enter")
        if r.returncode != 0:
            print("\nSEND FAILED, stopping rather than pretending it landed:")
            print("   ", (r.stdout + r.stderr).strip()[:300])
            return 2
        approvals += 1
        print("    approved (Enter)")

        # Give the session a moment to act, then require evidence that it did.
        # An approval that changes nothing means the keystroke is not reaching the
        # prompt, and looping harder has never once fixed that.
        grew_by = time.time() + 30
        while time.time() < grew_by:
            time.sleep(a.poll)
            if len(sw.records(sw.latest(a.repo))) != last_count:
                break
        else:
            print("\nNo new transcript records after that approval.")
            print("The keystroke is not reaching the prompt. Stopping for a human.")
            return 2

        last_count = len(sw.records(sw.latest(a.repo)))
        last_change = time.time()

    print(f"TIMEOUT after {a.timeout}s with {approvals} approval(s) given.")
    print("The agent may still be working. Screenshot before concluding anything.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
