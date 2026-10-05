#!/usr/bin/env python3
"""
ticket_tools.py – All-in-one Ticket / Port-22 / Reboot tool
==========================================================
Run:
  python3 ticket_tools.py

Menu:
  1) Filter tickets + Port-22 check
  2) Reboot Unreachable (from last ticketq result)
  3) Reboot by manual IP input
  4) Reinstall by manual IP input
  5) Recreate by manual IP input
  6) Filter only (skip port check)
  7) Dry-run reboot preview (from last result)
  8) Recreate ticket-flagged hosts (from last ticketq result)
  9) Dry-run recreate preview (ticket-flagged, from last result)
  0) Exit

KNOWN GOTCHAS (learned the hard way — don't reintroduce these):

1. HTTP header names are case-insensitive, but JS object keys are NOT.
   If you capture the same header under two different casings
   (e.g. "X-Jwt-Token" vs "x-jwt-token") and pass both as separate keys
   into fetch()'s headers object, fetch() silently joins the two values
   with ", " — producing a garbled combined string. The server error
   was "invalid number of segments" — that's the tell for this bug.
   Fix: always dedupe captured header names case-insensitively (lowercase
   key -> canonical name) BEFORE building the outgoing headers object.
   See _sanitize_jwt_map().

2. These JWTs are short-lived (~1hr) and issued per-partition
   (i18n / i18n-bd / eu-ttp each get their own token — don't clone one
   into another header). A structurally valid JWT (3 segments, "eyJ"
   prefix) can still be expired — always decode and check the `exp`
   claim before trusting a cached/saved token. The server error was
   "crypto/rsa: verification error" for a stale one.
   See _jwt_is_live() / _jwt_exp().

3. Never paste a live JWT / session cookie / curl-with-headers into a
   chat, ticket, or doc to debug this. Redact token values (keep header
   names + url) before sharing captured auth traffic anywhere.

4. DATA SOURCE REMINDER (easy to forget, ask about this before anything
   else): menu option 1/6 (do_ticketq) reads a `Tickets*.xlsx` from disk
   via find_latest_ticket_export() — a static snapshot with whatever
   columns that export happened to include.
    As of 2026-09-14, option "E" can fetch that snapshot itself for I18N or
    EUTTP: export_tickets_from_web() POSTs the selected region's
    /app/fault/ticket/export endpoint (confirmed via captured DevTools/curl
    responses to return raw PK-zip bytes synchronously, with no job/poll step)
    and saves the returned .xlsx directly. Option "E" can also run BOTH
    regions, merging them into one region-tagged workbook before filtering.
    Port-22 checks then dispatch each row to its region's connection-check site.
   Before answering, debugging, or proposing a fix for anything about
   ticket DATA SHAPE — e.g. "does `detail` contain a region/partition
   marker", "is there a region/site column", "why is field X
   missing/wrong" — still ask the user to confirm what's actually in
   their current export (paste a sample row / column list, or run option
   E for fresh i18n data) rather than guessing from code alone.
"""

# ============================================================
# WIP: AUTO-ESCALATING PIPELINE (reboot -> reinstall -> recreate)
# ============================================================
# Design as of 2026-09-10. Goal: after submitting a reboot, automatically
# monitor for completion, and on failure escalate the IP to reinstall,
# then recreate, updating the user/Excel at each stage instead of
# stopping at "ticket submitted". NOT YET IMPLEMENTED — the polling
# design itself is now fully resolved (see below); this block is the
# running summary kept here so it survives between sessions.
#
# CHOSEN ARCHITECTURE (agreed, not yet implemented):
#   - Persist pipeline state per IP in a JSON file (not just Excel), since
#     Excel is a bad source of truth for something that mutates over a
#     long-running, resumable process (file locks if open, no natural
#     read-modify-write safety).
#   - A single background worker thread owns the Playwright browser
#     exclusively (Playwright's sync API is NOT thread-safe) and polls;
#     the main menu thread only reads/writes the JSON state (never talks
#     to Playwright directly) so the menu stays responsive.
#   - Resumable: a "check pipeline status" menu option reads the JSON
#     state directly, works even if the script was closed and reopened,
#     and can restart the worker thread if it isn't currently running.
#
# RESOLVED PASS/FAIL POLLING CHAIN (fully closed, ready to implement):
#   1. Submit reboot/reinstall/recreate -> get the PARENT ticket_id
#      (already returned by our own /api/resource/operate calls).
#   2. Poll parent  GET /tickets/{parent_id}/action
#      -> scan data.ticket_nodes[] for the call_activity node that is
#         actually executing (has a real, non-zero-timestamp state —
#         NOT one of the untouched sibling branches, e.g. the
#         "close ticket" branch that never ran in our test case) ->
#         note its node_key.
#   3. Call GET /tickets/{parent_id}/nodes/{node_key}/sub_tickets
#         ?identifier={parent_id}&node_key={node_key}&page=1&page_size=10
#      -> returns the REAL child ticket(s): uuid, state, process_key,
#         parent_ticket_uuid, parent_node_key. THIS is the true pass/
#         fail source — the parent's own top-level state can (and does)
#         stay "running" forever even after the real operation has
#         already failed, so never trust the parent's state alone.
#   4. Child state == "failed"  -> escalate to next tier. Pull the
#         human-readable reason from that child's own
#         GET /tickets/{child_id}/variables -> look for an
#         operation-specific "*_detail" field (e.g. "reboot_detail" held
#         a raw OCI 409 Conflict message in testing; expect
#         reinstall_detail / recreate_detail analogues, unconfirmed).
#      Child state == "finished" -> pass.
#      Child state == "running"  -> keep polling.
#   Port-22 reachability (already implemented, via run_port22_checks) is
#   used as a fast pre-check only (definite-unreachable = fail fast,
#   don't wait out the full Alto timeout) — NOT as the primary pass
#   signal, since a host can be reachable while a real client-side/
#   filesystem-level failure still occurred. Alto's own state is what
#   actually decides pass/fail.
#
# ALTO TICKET-AUDIT API (reverse-engineered via DevTools):
#   Base:   https://{alto_domain}/flow/api/v1/tickets/{ticket_id}
#           (ticket_id == the ticketId already returned by our own
#           /api/resource/operate?action=Reboot|Reinstall|Recreate calls)
#   Auth:   COOKIE-based, NOT the X-Jwt-Token headers used elsewhere in
#           this script. Cookies seen: `alto-authorization` + `csrftoken`
#           + `alto_lang` + `org_tenant_number` (byteintl.net additionally
#           had a `bd_sso_<hash>` SSO cookie — unconfirmed whether EUTTP
#           sets an equivalent, not blocking either way), with csrftoken
#           duplicated into an `X-CSRF-Token` request header (Django
#           double-submit CSRF pattern). Needs its own
#           get_playwright_page()-style helper per alto_domain — the
#           existing _captured_jwt_headers machinery (for ie-oci.
#           tiktok-row.net) does not apply to any Alto domain.
#   Endpoints (all GET, `?identifier={ticket_id}` alongside unless noted):
#     /{ticket_id}                    - base ticket info (never actually
#                                        inspected body-for-body; not
#                                        needed, /action supersedes it)
#     /{ticket_id}/variables          - input params (ip_list, operate
#                                        type, vendor, etc.) PLUS, on a
#                                        failed child ticket, an
#                                        operation-specific "*_detail"
#                                        field with the raw underlying
#                                        error (see step 4 above)
#     /{ticket_id}/action             - ticket + node states (see chain
#                                        above). data.completed_at only
#                                        reliably flips non-zero on
#                                        SUCCESS, stays 0 on failure —
#                                        don't use it as a settled check
#     /{ticket_id}/histories?page=1&page_size=30
#                                      - paginated audit log; a failed
#                                        node shows category:"task",
#                                        result:"result.task_execution_
#                                        failed", context.error_message
#                                        (same content as *_detail) —
#                                        redundant confirmation, not
#                                        required if /action+sub_tickets
#                                        already checked
#     /{ticket_id}/nodes/{node_key}/sub_tickets?...&page=1&page_size=10
#                                      - ** the real child-ticket list **
#                                        (see step 3 above)
#     /{ticket_id}/{node_uuid}?node_uuid=...&ticket_uuid=...
#                                      - generic per-node detail (name,
#                                        type, timestamps, tasks/inputs/
#                                        outputs). Dead end for our
#                                        purposes: tasks/inputs/outputs
#                                        stayed null even on an executed,
#                                        finished node. Not needed once
#                                        sub_tickets was found.
#
#   Node-level `state` strings vary by node_type: gateway/start/end use
#   "finished"; user_task (human approval) uses "approved"; call_activity
#   subprocess nodes use "running"/"finished". Treat "not running/not
#   pending" as settled rather than matching one universal string.
#
#   The reboot flow (inner_ops_flow) branches by host count/risk:
#     低风险<10台 (low risk) -> Exclusive gateway -> one of:
#       重启 (reboot) / 重装 (reinstall) / 关闭故障单 (close ticket) /
#       未挂树退还 (un-mount return)  -- each its own SubProcess
#     高风险>=10台 (high risk) -> routes to a manual "Review" user_task
#       first, then the same Exclusive gateway once approved.
#   IMPORTANT: some tickets pause on that "Review" user_task waiting for
#   a human to approve — an unattended poller must treat "awaiting
#   approval" as a distinct state from "running"/"failed" and surface it
#   rather than silently waiting forever or misreading it as stuck.
#
# MULTI-REGION / MULTI-DOMAIN (confirmed real, not hypothetical):
#   Alto is deployed separately per region behind different domains
#   (found via the frontend's own region map in page source):
#     sg      -> alto2-bd.byteintl.net        (everything above was
#                                               reverse-engineered here)
#     euttp   -> alto2euttp.tiktok-eu.org     (confirmed via a real
#                                               EUTTP ticket)
#     va      -> alto2.tiktok-row.net (+ -ttp-eu/-ttp-us/-ttp2-us)
#     cn      -> alto2.bytedance.net / alto2boe.byted.org
#     oci(ttp)-> alto2.tiktok-usts.net (+ -ttp2)
#   CONFIRMED: schema is IDENTICAL across at least sg and euttp — same
#   process_key ("inner_ops_flow"), same ticket_nodes[] shape, and the
#   reboot SubProcess node_key (node_1f13a249ee4e627086b55249f97d5fe3)
#   is the exact same literal value on both domains, meaning flow/node
#   definitions are shared across deployments. So the polling LOGIC
#   above needs zero per-domain special-casing — only the base URL and
#   the auth session differ per domain.
#   The submit page itself (https://ie-oci.tiktok-row.net/compute/host)
#   is shared across regions too — no change needed there.
#   STILL OPEN: how does the script know WHICH alto_domain to poll for a
#   given submitted ticket (I18N vs EUTTP)? Two candidates, unconfirmed:
#     (a) the submit API's own response may carry a region/domain hint
#         directly (check a raw submit response body)
#     (b) derivable from something already in the ticketq pipeline data
#         per IP (a region/vendor column, or convention) — TBD whether
#         the source Tickets*.xlsx / ticketq output already carries this
#   Track pipeline state keyed by (IP, alto_domain, ticket_id), not just
#   (IP, ticket_id), once this is resolved. If genuinely multi-domain in
#   practice, the worker thread needs a separate authenticated
#   Playwright page per alto_domain in use (each with its own cookies),
#   not one shared session.
#   REQUESTED UX: when this is resolved, add a region prompt (I18N vs
#   EUTTP) to the ticketq/filter menu option, so filtering pulls tickets
#   for the chosen region accordingly — exact mechanism depends on how
#   (b) above shakes out.
#
#   SECURITY: several live session cookies / SSO tokens / CSRF tokens have
#   been shared in chat while reverse-engineering this. Rotate/re-auth
#   affected Alto sessions periodically, and never commit real cookie
#   values anywhere (see gotcha #3 above — same rule applies to Alto
#   cookies as to the X-Jwt-Token values).
# ============================================================

import sys
import base64
import json
import os
import re
import tempfile
import threading
import time
import subprocess
import platform
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import urlparse

import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils.dataframe import dataframe_to_rows
from openpyxl.utils import get_column_letter

# ============================================================
# CONFIG
# ============================================================
EXCLUDE_PRODUCT_KEYWORDS = ["GPU", "VM", "BigData"]
EXCLUDE_OPERATORS = [
    "chinboonleow",
    "edwinlim",
    "gilberttan",
    "jamestsui",
    "chenfuqiao",
    "fuqiao.chen",
]
EXCLUDE_PSM_KEYWORDS = ["system.cloud"]

# Both fault sites use the same synchronous XLSX export API and request shape.
# Keep their configurations separate so a token/page from one partition is not
# silently reused for the other. EUTTP's export endpoint was confirmed from
# the captured curl on 2026-09-14.
# Same JWT-capture auth as fetch_fault_ticket_detail() (X-Jwt-Token header,
# same site). `export` column list below is copied from a real captured
# request body and already lines up with what apply_filters()/enrich()
# expect (id/type/detail/ipv4/ipv6/sn/host_sn/product/... etc).
REGION_CONFIG = {
    "i18n": {
        "label": "I18N",
        "export_api": "https://fault-i18n.tiktok-row.net/app/fault/ticket/export",
        "export_page": "https://fault-i18n.tiktok-row.net/fault?manufacturer=oci&progress=to_be_confirmed",
        "port_api": "https://saos-i18n.tiktok-row.net/app/operation/connection_check",
        "port_page": "https://saos-i18n.tiktok-row.net/operation/port-test",
        "port_mode": "direct",
        "output_prefix": "Tickets_I18N_export",
    },
    "euttp": {
        "label": "EUTTP",
        "export_api": "https://fault.tiktok-eu.net/app/fault/ticket/export",
        "export_page": "https://fault.tiktok-eu.net/fault?manufacturer=oci&progress=to_be_confirmed",
        "port_api": "https://saos-eu.tiktok-eu.net/app/saos/ttp-proxy",
        "port_target_api": "https://saos-eu.tiktoke.org/app/operation/connection_check",
        "port_page": "https://saos-eu.tiktok-row.net/operation/port-test",
        "port_mode": "ttp_proxy",
        "output_prefix": "Tickets_EUTTP_export",
    },
}
REGION_CHOICES = {"1": "i18n", "2": "euttp", "3": "both"}

# Backward-compatible aliases for the I18N-only detail lookup below.
EXPORT_API = REGION_CONFIG["i18n"]["export_api"]
EXPORT_PAGE = REGION_CONFIG["i18n"]["export_page"]
EXPORT_COLUMNS = [
    "id", "ip", "type", "detail", "product_line", "request_psm_name", "product",
    "model", "allow_psm_name", "not_allow_psm_name", "progress", "created",
    "operator_name", "host_type", "sn", "ipv4", "ipv6", "host_sn", "manufacturer",
]

# fault-i18n.tiktok-row.net — per-ticket detail lookup (mount-point check for
# the filesystem/"FS Readonly From Mount" fault). Confirmed via curl: GET
# {FAULT_TICKET_DETAIL_URL_TEMPLATE} with Accept: application/json returns
# real JSON (not HTML) — mount point lives at backup_list[].mount, matched
# EXACTLY against "/" (not a substring — "/data00" must NOT match).
FAULT_TICKET_PAGE_TEMPLATE = "https://fault-i18n.tiktok-row.net/fault/{ticket_id}"
FAULT_TICKET_DETAIL_URL_TEMPLATE = "https://fault-i18n.tiktok-row.net/app/fault/ticket/{ticket_id}/detail"
FILESYSTEM_DETAIL_KEYWORDS = ["FS Readonly From Mount"]

# OS EIPv4 + EIPv6 unreachable tickets get their own diagnostic workflow
# (menu option N): OCI IPv6 lookup -> secondary IPv4/IPv6 SAOS check ->
# NIC-state Aries -> Recreate or Reinstall -> post-Reinstall SAOS -> Recreate.
DUAL_IP_DETAIL_KEYWORDS = [
    "OS EIPv4 and EIPv6 unreachable",
    "Link Down：Min <= (DayCount) < Max",
]
# Disk/NVMe-lost faults (added 2026-09-15). Intended process, per the user:
#   1. Query https://ie-oci.tiktok-row.net/batch_query for this host's
#      maintenance_event state.
#   2. If that state is "SCHEDULED" -> start the Recreate pipeline.
#   3. If NOT "SCHEDULED" -> run the Aries shell-script check at
#      https://aries.tiktok-row.org/modification/modificationList/launch?maintainer=edwinlim.rciw
#      — its output then determines different manually-raised outcomes.
# NOT YET AUTOMATED — do_ticketq() below only detects and separates these
# tickets into their own workbook for now; it does NOT call either external
# check. Needed before that can be wired up (same discipline as every other
# endpoint in this file — captured, not guessed):
#   (a) A curl of the batch_query request: what identifier does it take
#       (IP? SN? instance_id?), method, and the real response shape — so we
#       know the exact path/field to read "maintenance_event"/"state" from.
#   (b) Whether the Aries "launch" URL is itself curl-able (returns
#       JSON/text output directly) or is a page requiring manual
#       interaction (click "Run", wait for script stdout in the UI). If
#       curl-able: what identifier it needs as input.
#   (c) The full list of distinct possible outputs from that Aries script,
#       and which manual outcome/action each one maps to — "different
#       manually raised outcomes" was mentioned but not yet enumerated.
#   (d) Whether `?maintainer=edwinlim.rciw` is fixed to this one account or
#       needs to vary per whoever is running the script.
DISK_LOST_DETAIL_KEYWORDS = [
    "All disks are unrecognized",
    "Disk: Lost (Unrecognized)",
    "Disk: Lost (unable to locate specific slot)",
    "Disk: No Mounted (Formatted; Smart OK )",
    "NVME: Lost (in System lost but in lspci exist)",
]

# NVMe QID-timeout/reset-controller faults (added 2026-09-23). Confirmed
# process, per the user: run the SAME Aries "check NVMEs" script as the
# disk-lost flow above (same unitID/version/script — see
# ARIES_REGION_CONFIG / ARIES_NVME_CHECK_SCRIPT), just with the deploy-side
# script-execution timeout raised from the usual 200s to 660s (this is
# Aries' own per-host timeout field, deployStrategy.simple.control.timeout —
# NOT our own polling timeout — see ARIES_NVME_TIMEOUT_RESET_DEPLOY_TIMEOUT_SECONDS).
# Outcome routing reuses classify_taskdetail_entry()'s existing categories:
#   agent_lost                              -> Recreate the instance
#   failed, any other classification        -> OCI SR (instance batch_list +
#     (missing_drive/unrecognized_shape/       build_sr_draft_for_completed_aries_host(),
#      generic_failure)                        same generic per-host SR generation the
#                                                D-workflow already uses)
#   pass                                    -> Reinstall, then verify the fault
# "Verify fault" = CLOSING THE FAULT TICKET on the fault platform (confirmed
# 2026-09-28). That is deliberately left MANUAL: there is no ticket-retrieval/
# close workflow in this script, and the user prefers closing them by hand.
# do_nvme_timeout_reset_workflow() submits the Reinstall, then lists the
# fault ticket ids to close and marks them in the output workbook.
NVME_TIMEOUT_RESET_DETAIL_KEYWORDS = [
    "NVME QID 0 timeout,reset controller",  # confirmed exact text (2026-09-23, ASCII comma)
    "NVME QID 0 timeout，reset controller",  # kept as a fallback in case some tickets use a full-width comma
]
ARIES_NVME_TIMEOUT_RESET_DEPLOY_TIMEOUT_SECONDS = 660

# ---- ADD NEW `detail`-BASED TICKET TYPES HERE ----------------------------
# apply_filters() pulls a ticket in if its `type` matches ping|ssh (below)
# OR its `detail` text contains any string from EITHER of the two lists
# below. Matching is case-insensitive substring — no regex escaping needed,
# just paste the phrase as it appears in the `detail` column.
#
# INCLUDE_DETAIL_KEYWORDS  -> ticket goes through the normal flow (port-22
#                              check -> reboot if unreachable). Use this for
#                              new "reachability-style" alarms.
# RECREATE_DETAIL_KEYWORDS -> ticket skips the port-22 check entirely and is
#                              routed straight to "Recreate candidate"
#                              (menu option 8/9). Use this for host-health /
#                              degraded-host alarms where reachability isn't
#                              the signal.
#
# To add a new detail string: just append it to the relevant list below.
# Nothing else in the script needs to change.
INCLUDE_DETAIL_KEYWORDS = [
    "OS all IP unreachable",
    "SSH Unreachable",
    "FS Readonly From Mount",
]

RECREATE_DETAIL_KEYWORDS = [
    "OCI: 409 Degraded Host",
    "cloud server reboot alarm need diagnosis",
    "cloud server alarm need diagnosis",
]
# ---------------------------------------------------------------------------

PORT_TEST_URL = REGION_CONFIG["i18n"]["port_api"]
PORT_TEST_PAGE = REGION_CONFIG["i18n"]["port_page"]
PORT_BATCH_SIZE = 30

REBOOT_API = "https://ie-oci.tiktok-row.net/api/resource/operate?action=Reboot"
REBOOT_PAGE = "https://ie-oci.tiktok-row.net/operation?action=Reboot"
REBOOT_BATCH_SIZE = 10  # unused — reboots are now submitted one IP per request (see run_reboots), since mixed-PSM batches were silently getting rejected server-side
REINSTALL_API = "https://ie-oci.tiktok-row.net/api/resource/operate?action=Reinstall"
REINSTALL_PAGE = "https://ie-oci.tiktok-row.net/operation?action=Reinstall"
RECREATE_API = "https://ie-oci.tiktok-row.net/api/resource/operate?action=Recreate"
RECREATE_PAGE = "https://ie-oci.tiktok-row.net/operation?action=Recreate"
UNHEALTHY_TAG_PAGE = "https://ie-oci.tiktok-row.net/operation?action=UpdateInstanceUnhealthyTag"
# Shapes handled by menu option G (tag unhealthy -> recreate). Matched case-insensitively,
# exactly, against the ticket `product` / `model` columns.
GPU_RECREATE_SHAPES = ["BM.GPU.L40S-NC.4", "BM.GPU.A10.4", "BM.GPU.T1.2"]
JWT_REFRESH_URL = "https://proxy-tcc.bytedance.net/bytecloud.fe.config/jwt"
# ============================================================


# ============================================================
# PIPELINE STATE — persistent, resumable state for the auto-escalating
# reboot -> reinstall -> recreate pipeline.
#
# WHY JSON, NOT EXCEL:
# Excel is a snapshot format — every *_result_*.xlsx is written once when a
# menu option finishes and never touched again. This state mutates
# constantly in the background (worker thread polling Alto) and needs safe
# concurrent read-modify-write from two threads (main menu thread + worker
# thread) plus resumability across script restarts. Excel gives none of
# that. This section is the single source of truth for "what is currently
# happening"; Excel outputs remain pure historical submit records.
#
# CONCURRENCY MODEL:
# Both the main thread (submitting new ops / reading for the summary line)
# and the worker thread (updating status as it polls Alto) touch this file.
# Writes are atomic via write-to-temp-then-os.replace(), which is atomic on
# both POSIX and Windows, so a reader never sees a half-written file. This
# is NOT full cross-process locking — it's last-write-wins on the whole
# file, which is fine here because updates are small, infrequent (poll
# interval, not per-millisecond), and each caller does read-modify-write in
# one function call, minimizing the race window. Fine for a single-process,
# two-thread script; would need `filelock` if ever run as multiple
# concurrent processes against the same folder.
#
# SCHEMA (one JSON object, keyed by IP):
# {
#   "10.1.2.3": {
#     "stage": "reboot",              # "reboot" | "reinstall" | "recreate"
#     "ticket_id": "ticket_7f3f...",
#     "ticket_url": "https://alto2.tiktok-row.net/.../ticket_7f3f...",
#     "alto_domain": "alto2.tiktok-row.net",   # derived from ticket_url netloc
#     "partition": "I18N",                     # from submit response, cross-check only
#     "child_ticket_id": "",                   # filled once /sub_tickets resolves it
#     "state": "running",             # "running" | "finished" | "failed" |
#                                      # "awaiting_recreate_approval"
#     "detail": "",                   # human-readable reason on failure/escalation
#     "source": "menu:reboot",        # which menu option/action created this entry
#     "created_at": "2026-09-10T12:00:00",
#     "updated_at": "2026-09-10T12:00:00"
#   },
#   ...
# }
#
# Only one entry per IP at a time. An IP moves through stages by being
# overwritten in place (stage changes reboot -> reinstall -> recreate), not
# by accumulating multiple entries — so "is this IP already in-flight" is
# always a single dict lookup, not a scan.
# ============================================================

PIPELINE_STATE_FILE = Path(__file__).resolve().parent / ".ticket_tools_pipeline_state.json"
DUAL_IP_STATE_FILE = Path(__file__).resolve().parent / ".ticket_tools_dual_ip_state.json"

# In-process lock. Guards against the main thread and worker thread both
# doing read-modify-write at the exact same instant *within this process*.
# The atomic replace protects file-level integrity even without this, but
# this closes the narrower "two threads both read old content, both write
# back, second write clobbers the first's change" race.
_pipeline_lock = threading.Lock()

# Stages, in escalation order. Used by pipeline_next_stage() so the worker
# doesn't hardcode the chain in multiple places.
PIPELINE_STAGE_ORDER = ["reboot", "reinstall", "recreate"]

# States that mean "this IP needs the person's attention" — used by the
# menu summary line to decide what to name explicitly vs. fold into a count.
PIPELINE_ATTENTION_STATES = {"failed", "awaiting_recreate_approval", "awaiting_review"}

# States that mean "still actively being tracked" — used by the exit-guard
# and the duplicate-submission overlap check.
PIPELINE_IN_FLIGHT_STATES = {"running", "awaiting_recreate_approval"}


# Number of tickets to process before asking whether to continue.
# Change this single value later (for example, to 10) to change the batch size.
ARIES_BATCH_SIZE = 5

def _pipeline_now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _pipeline_read_raw() -> dict:
    """Reads the state file. Returns {} if it doesn't exist yet or is empty/
    corrupt — a corrupt state file should never crash the script; worst case
    we lose live tracking, which is recoverable (Alto tickets keep running
    server-side regardless), not a data-loss event."""
    if not PIPELINE_STATE_FILE.exists():
        return {}
    try:
        text = PIPELINE_STATE_FILE.read_text(encoding="utf-8").strip()
        if not text:
            return {}
        return json.loads(text)
    except (json.JSONDecodeError, OSError):
        return {}


def _pipeline_write_raw(data: dict):
    """Atomic write: write to a temp file in the same directory, then
    os.replace() over the real path. os.replace is atomic on POSIX and
    Windows, so a concurrent reader always sees either the old file or the
    new one in full — never a half-written truncated file."""
    PIPELINE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=str(PIPELINE_STATE_FILE.parent), prefix=".pipeline_state_", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp_path, PIPELINE_STATE_FILE)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def pipeline_alto_domain_from_ticket_url(ticket_url: str) -> str:
    """Extracts the alto_domain from a ticketUrl, e.g.
    'https://alto2.tiktok-row.net/T0000.../ticket-audit/ticket_xxx'
    -> 'alto2.tiktok-row.net'. No separate domain-lookup step needed —
    the submit response already carries this."""
    if not ticket_url:
        return ""
    return urlparse(ticket_url).netloc


def pipeline_start_entry(ip: str, *, stage: str, ticket_id: str, ticket_url: str,
                          partition: str = "", source: str = "") -> dict:
    """Creates or overwrites the tracked entry for an IP at the start of a
    new stage (initial submit, or an escalation moving reboot -> reinstall
    -> recreate). Call this right after a successful submit response comes
    back."""
    with _pipeline_lock:
        data = _pipeline_read_raw()
        now = _pipeline_now()
        existing = data.get(ip, {})
        data[ip] = {
            "stage": stage,
            "ticket_id": ticket_id,
            "ticket_url": ticket_url,
            "alto_domain": pipeline_alto_domain_from_ticket_url(ticket_url),
            "partition": partition,
            "child_ticket_id": "",
            "state": "running",
            "detail": "",
            "source": source or existing.get("source", ""),
            "created_at": existing.get("created_at", now),
            "updated_at": now,
        }
        _pipeline_write_raw(data)
        return data[ip]


def pipeline_update_entry(ip: str, **fields) -> dict:
    """Merges fields into an existing entry (e.g. state, detail,
    child_ticket_id) and bumps updated_at. Used by the worker thread as it
    polls. No-op (returns {}) if the IP isn't tracked — use
    pipeline_start_entry to create a new entry, not this."""
    with _pipeline_lock:
        data = _pipeline_read_raw()
        if ip not in data:
            return {}
        data[ip].update(fields)
        data[ip]["updated_at"] = _pipeline_now()
        _pipeline_write_raw(data)
        return data[ip]


def pipeline_all_entries() -> dict:
    with _pipeline_lock:
        return _pipeline_read_raw()


def pipeline_clear_entry(ip: str):
    """Removes an IP from tracking entirely — e.g. once it's confirmed
    passed and there's no value in keeping it in the live state file
    (history lives in the Excel outputs instead)."""
    with _pipeline_lock:
        data = _pipeline_read_raw()
        if ip in data:
            del data[ip]
            _pipeline_write_raw(data)


def pipeline_next_stage(current_stage: str) -> str:
    """Returns the next stage in the escalation chain, or '' if
    current_stage is already the last one (recreate) or unrecognized."""
    try:
        idx = PIPELINE_STAGE_ORDER.index(current_stage)
    except ValueError:
        return ""
    if idx + 1 < len(PIPELINE_STAGE_ORDER):
        return PIPELINE_STAGE_ORDER[idx + 1]
    return ""


def pipeline_check_overlap(ip_list: list) -> dict:
    """Duplicate-submission guard. Checks a list of IPs about to be
    submitted against currently in-flight pipeline entries. Returns a dict
    of {ip: entry} for only the IPs that are already running or awaiting
    recreate approval — i.e. the ones that need a confirm prompt before
    resubmitting. Does NOT itself prompt or block; see
    pipeline_confirm_overlap for that."""
    with _pipeline_lock:
        data = _pipeline_read_raw()
    overlaps = {}
    for ip in ip_list:
        entry = data.get(str(ip).strip())
        if entry and entry.get("state") in PIPELINE_IN_FLIGHT_STATES:
            overlaps[ip] = entry
    return overlaps


def pipeline_confirm_overlap(ip_list: list) -> list:
    """Runs pipeline_check_overlap() and, for any hits, prompts per-IP
    before letting a submit proceed. Returns the filtered ip_list with any
    IP the person declined to resubmit removed. Called at the top of each
    do_* submit function, before the run_* call."""
    overlaps = pipeline_check_overlap(ip_list)
    if not overlaps:
        return ip_list

    keep = list(ip_list)
    for ip, entry in overlaps.items():
        stage = entry.get("stage", "?")
        state = entry.get("state", "?")
        state_label = "awaiting recreate approval" if state == "awaiting_recreate_approval" else state
        answer = input(
            f"  {ip} already has a {stage} in-flight ({state_label}) — "
            f"submit anyway? [y/N]: "
        ).strip().lower()
        if answer != "y":
            keep = [x for x in keep if str(x).strip() != str(ip).strip()]
            print(f"    Skipping {ip}.")
    return keep


def pipeline_attention_summary() -> dict:
    """Splits current entries into (needs_attention, running_count) for the
    menu summary line: named IPs for anything in PIPELINE_ATTENTION_STATES,
    a plain count for everything else still running."""
    data = pipeline_all_entries()
    needs_attention = {
        ip: entry for ip, entry in data.items()
        if entry.get("state") in PIPELINE_ATTENTION_STATES
    }
    running_count = sum(1 for entry in data.values() if entry.get("state") == "running")
    return {"needs_attention": needs_attention, "running_count": running_count, "total": len(data)}


# ============================================================


# -------------------- persistent browser --------------------
_browser = None
_context = None
_playwright = None
_pages_by_target = {}
BROWSER_DATA_DIR = Path(__file__).resolve().parent / ".ticket_tools_browser"
# SECURITY NOTE (2026-09-18): this file holds a live bearer JWT in
# PLAINTEXT — the same class of credential redacted out of every curl in
# this project's history. Short-lived (~1hr, see _jwt_is_live) bounds the
# damage, but a plaintext token sitting in the script's own folder is one
# `git add .`, backup, sync, or screen-share away from leaking. _save_jwt_to_file()
# below chmods it 0600 (owner-only) as a defense-in-depth measure, but that
# doesn't help once it leaves this machine — never commit, attach, or paste
# this file's contents anywhere, and don't sync this folder to a shared drive.
JWT_FILE = Path(__file__).resolve().parent / ".ticket_tools_jwt"


def _launch_persistent_browser_context():
    """Launch a Playwright-controlled persistent context.

    Chromium refuses to attach when the preferred user-data directory is
    already owned by another browser process ("Opening in existing browser
    session"). In that case, retry with a fallback profile instead of leaving
    the user on an uncontrollable about:blank page.
    """
    preferred = BROWSER_DATA_DIR
    fallback = BROWSER_DATA_DIR.parent / f"{BROWSER_DATA_DIR.name}_fallback"
    session_fallback = BROWSER_DATA_DIR.parent / f"{BROWSER_DATA_DIR.name}_session_{os.getpid()}"
    candidates = [preferred, fallback, session_fallback]
    last_error = None

    for index, profile_dir in enumerate(candidates):
        profile_dir.mkdir(parents=True, exist_ok=True)
        print(f"(Using persistent browser profile: {profile_dir})")
        try:
            return _playwright.chromium.launch_persistent_context(
                user_data_dir=str(profile_dir),
                headless=False,
                viewport={"width": 1280, "height": 800},
            )
        except Exception as exc:
            last_error = exc
            message = str(exc)
            profile_in_use = (
                "Opening in existing browser session" in message
                or "profile is already in use" in message.lower()
                or "process singleton" in message.lower()
            )
            if not profile_in_use or index == len(candidates) - 1:
                raise
            print(f"  Browser profile is already in use: {profile_dir}")
            print("  Retrying with a separate Playwright profile for this run...")

    raise RuntimeError(f"Unable to launch a Playwright browser context: {last_error}")


# Captured JWT headers from real browser traffic (filled by request listener)
_captured_jwt_headers = {}
_last_sr_drafts = []  # set by do_disk_lost_aries_workflow(), read by do_fill_sr_form_test()
_sr_form_pages = []
SR_FORM_PAGE_LIMIT = 20  # prevent an unlimited number of unsubmitted SR tabs


def _jwt_exp(token: str):
    """Decode a JWT's payload (no signature check) and return its exp claim, or None."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)  # pad for base64url
        data = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")))
        return data.get("exp")
    except Exception:
        return None


def _jwt_is_live(token: str, skew_seconds: int = 30) -> bool:
    """True if the token structurally looks like a JWT AND its exp claim (if present)
    is still in the future (with a small safety margin). These tokens are short-lived
    (~1 hour), so a saved/captured token can easily be stale by the time it's used."""
    if not token or not token.startswith("eyJ") or token.count(".") != 2:
        return False
    exp = _jwt_exp(token)
    if exp is None:
        # No exp claim readable — don't block on it, but this is the exception not the rule.
        return True
    return time.time() < (exp - skew_seconds)


def _load_jwt_from_file() -> str:
    """Load a manually saved JWT from .ticket_tools_jwt next to the script."""
    try:
        if JWT_FILE.exists():
            val = JWT_FILE.read_text(encoding="utf-8").strip()
            if val.lower().startswith("bearer "):
                val = val[7:].strip()
            if val.startswith("eyJ") and val.count(".") == 2:
                if not _jwt_is_live(val):
                    print("  Saved JWT file is expired; ignoring it (will need a fresh capture).")
                    return ""
                return val
    except Exception:
        pass
    return ""


def _save_jwt_to_file(token: str):
    try:
        JWT_FILE.write_text(token.strip() + "\n", encoding="utf-8")
        try:
            # Defense in depth: restrict to owner read/write only. Best-effort —
            # os.chmod is a no-op-ish on Windows, hence the broad except.
            os.chmod(JWT_FILE, 0o600)
        except Exception:
            pass
        print(f"  Saved JWT to {JWT_FILE.name} for reuse (plaintext — see the "
              f"SECURITY NOTE above JWT_FILE's definition; don't share this file).")
    except Exception as e:
        print(f"  (Could not save JWT file: {e})")






def _sanitize_jwt_map(raw: dict) -> dict:
    """Keep only structurally valid, non-expired JWTs without cloning one token into
    other headers, AND without letting two different-cased captures of the SAME
    header (e.g. 'X-Jwt-Token' and 'x-jwt-token') survive together.

    That casing duplication matters: when both are set as separate keys on a plain
    JS object passed to fetch()'s headers, the Fetch API treats them as the same
    HTTP header and joins the two values with ", " — producing a garbled value with
    far more than 3 segments, which is exactly the "invalid number of segments"
    error from the server. So here we dedupe by lowercase header name, keeping a
    single canonically-cased entry per real header.

    The reboot page uses several X-Jwt-Token-* headers, and some of them can
    contain different JWTs. Preserve the browser-observed header/value pairs.
    """
    CANONICAL_NAMES = {
        "x-jwt-token": "X-Jwt-Token",
        "x-jwt-token-i18n": "X-Jwt-Token-I18N",
        "x-jwt-token-eu-ttp": "X-Jwt-Token-EU-TTP",
        "x-jwt-token-i18n-bd": "X-Jwt-Token-I18N-BD",
    }

    by_lower = {}  # lowered header name -> (original_key, value) — last live one wins
    for k, v in (raw or {}).items():
        if not v or not isinstance(v, str):
            continue
        val = v.strip()
        if val.lower().startswith("bearer "):
            val = val[7:].strip()
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        parts = val.split(".")
        if val.startswith("eyJ") and len(parts) == 3 and all(parts) and _jwt_is_live(val):
            by_lower[str(k).lower()] = val

    clean = {}
    for lower_key, val in by_lower.items():
        canonical = CANONICAL_NAMES.get(lower_key, lower_key)
        clean[canonical] = val

    # Only use the saved token as a last-resort primary token. Never copy it
    # into the other X-Jwt-Token-* headers.
    if not clean:
        file_jwt = _load_jwt_from_file()
        if file_jwt:
            clean["X-Jwt-Token"] = file_jwt
    return clean


def _page_jwt_headers(page) -> dict:
    """Read only the JWTs captured by this persistent browser tab."""
    try:
        raw = page.evaluate("() => window.__capturedJwtHeaders || {}")
        return _sanitize_jwt_map(raw if isinstance(raw, dict) else {})
    except Exception:
        return {}


def get_playwright_page(target_url: str, prompt_label: str = "page"):
    """
    Reuse a single visible browser + context for the whole dashboard session.
    Cookies/login persist while the script is running, and also across runs
    via a persistent user-data directory.
    Also listens for real requests to capture X-Jwt-Token headers.
    """
    global _browser, _context, _playwright
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("\nPlaywright is not installed. Run:")
        print("  pip install playwright")
        print("  playwright install chromium")
        sys.exit(1)

    if _playwright is None:
        _playwright = sync_playwright().start()

    if _context is None:
        _context = _launch_persistent_browser_context()
        _browser = _context

        def _on_request(request):
            try:
                headers = request.headers
                for hk, hv in headers.items():
                    if "jwt" not in hk.lower() or not hv:
                        continue
                    # Only keep structurally valid JWTs (3 segments)
                    parts = hv.strip().split(".")
                    if len(parts) == 3 and hv.strip().startswith("eyJ"):
                        _captured_jwt_headers[hk] = hv.strip()
            except Exception:
                pass

        _context.on("request", _on_request)

    target_key = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}{urlparse(target_url).path}"
    page = _pages_by_target.get(target_key)
    if page is None or page.is_closed():
        page = _context.new_page()
        _pages_by_target[target_key] = page

    # Install the browser-side interceptor BEFORE navigation so it survives the
    # page load. The old implementation reinstalled a fetch-only interceptor
    # after navigation, which could miss XHR-based authentication traffic.
    def _install_interceptor(p):
        p.add_init_script("""
        (() => {
          if (window.__jwtCaptureInstalled) return;
          window.__jwtCaptureInstalled = true;
          window.__capturedJwtHeaders = window.__capturedJwtHeaders || {};

          function isJwt(v) {
            if (!v || typeof v !== 'string') return false;
            const val = v.replace(/^Bearer\\s+/i, '').trim();
            const parts = val.split('.');
            return val.startsWith('eyJ') && parts.length === 3 && parts.every(Boolean);
          }

          function saveHeaders(h) {
            if (!h) return;
            const get = (k) => {
              if (h instanceof Headers) return h.get(k);
              if (typeof h === 'object') {
                const found = Object.keys(h).find(x => x.toLowerCase() === k.toLowerCase());
                return found ? h[found] : null;
              }
              return null;
            };
            ['X-Jwt-Token','X-Jwt-Token-I18N','X-Jwt-Token-I18N-BD','X-Jwt-Token-EU-TTP','Authorization'].forEach(name => {
              const v = get(name);
              if (isJwt(v)) {
                window.__capturedJwtHeaders[name] = v.replace(/^Bearer\\s+/i, '').trim();
              }
            });
          }

          const origFetch = window.fetch;
          window.fetch = function(input, init) {
            try {
              if (init && init.headers) saveHeaders(init.headers);
              if (input && input.headers) saveHeaders(input.headers);
            } catch (e) {}
            return origFetch.apply(this, arguments);
          };

          const origOpen = XMLHttpRequest.prototype.open;
          const origSetHeader = XMLHttpRequest.prototype.setRequestHeader;
          XMLHttpRequest.prototype.open = function() {
            this.__hdrs = {};
            return origOpen.apply(this, arguments);
          };
          XMLHttpRequest.prototype.setRequestHeader = function(k, v) {
            try { this.__hdrs[k] = v; saveHeaders(this.__hdrs); } catch (e) {}
            return origSetHeader.apply(this, arguments);
          };
        })();
        """)

    print(f"Opening {target_url}")
    print("→ If you are not logged in yet, log in now.")
    print("→ The script will watch the browser's real API traffic for JWT headers.")
    print("→ You do NOT need to copy/paste a JWT.")
    try:
        _install_interceptor(page)
        page.goto(target_url, wait_until="domcontentloaded", timeout=60000)
        # add_init_script applies to future documents; after navigation the
        # interceptor is already installed in this document.
    except Exception as e:
        print(f"  Navigation note: {e}")
        print("  (You can still log in manually in the open window.)")

    # Give normal page authentication/API initialization time to run.
    # If login is needed, allow the user to finish it before the second wait.
    # auto_detected tracks whether THIS page's own per-domain tokens showed up
    # without any manual action — used below to skip the redundant "press
    # ENTER" prompts on a page/domain that's already authenticated (e.g. a
    # cached tab reused across many calls in a loop, or a brand-new tab that's
    # already logged in thanks to the persistent browser profile's cookies).
    # Before this fix (2026-09-18), both prompts below fired unconditionally
    # on EVERY call regardless of readiness — turning any loop that opens
    # several pages/domains (batch polling, disk-lost/Aries workflow) into a
    # forced manual pause per iteration.
    import time
    auto_detected = False
    for _ in range(20):
        try:
            page_tokens = page.evaluate("() => window.__capturedJwtHeaders || {}")
            if isinstance(page_tokens, dict) and any(page_tokens.values()):
                auto_detected = True
                break
        except Exception:
            pass
        time.sleep(0.5)

    def _merge_page_tokens():
        try:
            page_tokens = page.evaluate("() => window.__capturedJwtHeaders || {}")
            if isinstance(page_tokens, dict):
                for k, v in page_tokens.items():
                    if v and str(v).startswith("eyJ") and str(v).count(".") == 2:
                        _captured_jwt_headers[str(k)] = str(v)
        except Exception:
            pass

    _merge_page_tokens()
    if not auto_detected:
        input("\n>>> Finish login / any normal page action, then press ENTER... ")
        # After the user completes authentication, give the site time to emit
        # its normal authenticated requests.
        for _ in range(30):
            _merge_page_tokens()
            if _captured_jwt_headers:
                auto_detected = True
                break
            time.sleep(0.5)
    else:
        print("  Authentication headers detected automatically.")

    _merge_page_tokens()
    if _captured_jwt_headers:
        print(f"  Captured JWT header(s): {list(_captured_jwt_headers.keys())}")
    else:
        print("  No JWT headers observed yet. The reboot step will wait for them before sending.")

    if auto_detected:
        print(f"  {prompt_label} already authenticated — skipping manual confirmation.")
    else:
        input(f"\n>>> Press ENTER after the {prompt_label} is ready... ")

    # Pull tokens captured inside the page
    try:
        page_tokens = page.evaluate("() => window.__capturedJwtHeaders || {}")
        if isinstance(page_tokens, dict):
            for k, v in page_tokens.items():
                if v and str(v).startswith("eyJ") and str(v).count(".") == 2:
                    _captured_jwt_headers[k] = v
    except Exception as e:
        print(f"  (Could not read page-captured tokens: {e})")

    if _captured_jwt_headers:
        print(f"  Captured JWT header(s): {list(_captured_jwt_headers.keys())}")
    else:
        print("  Still no JWT captured automatically.")
        print("  Fallback: paste X-Jwt-Token from DevTools (Network → any API request → Request Headers).")
        print("  Or press ENTER to skip (reboot may fail with 401).")
        pasted = input("  Paste token (or empty to skip): ").strip()
        if pasted:
            # allow "Bearer xxx" or raw jwt
            if pasted.lower().startswith("bearer "):
                pasted = pasted[7:].strip()
            if pasted.startswith("eyJ") and pasted.count(".") == 2:
                _captured_jwt_headers["X-Jwt-Token"] = pasted
                print("  Token accepted.")
                _save_jwt_to_file(pasted)
            else:
                print("  That does not look like a valid JWT (need 3 segments starting with eyJ). Ignored.")
    return page


def close_browser():
    global _browser, _context, _playwright, _pages_by_target, _sr_form_pages
    try:
        if _context is not None:
            _context.close()
    except Exception:
        pass
    try:
        if _playwright is not None:
            _playwright.stop()
    except Exception:
        pass
    _browser = None
    _context = None
    _playwright = None
    _pages_by_target = {}
    _sr_form_pages = []


# ============================================================
# ALTO SESSION + POLLING — cookie-based auth for Alto's ticket-audit API,
# parallel to the JWT machinery above but for a completely different system.
#
# WHY SEPARATE FROM THE JWT HELPER:
# ie-oci.tiktok-row.net (REBOOT_API/REINSTALL_API/RECREATE_API — what
# *submits* an operation) authenticates via X-Jwt-Token headers, captured by
# get_playwright_page(). Alto (what we *poll* afterward, for status) is a
# different application entirely and authenticates via cookies instead:
# `alto-authorization`, `csrftoken`, `alto_lang`, `org_tenant_number` (+ an
# SSO cookie on some domains — unconfirmed whether every domain sets one),
# with csrftoken's value duplicated into an X-CSRF-Token request header
# (Django double-submit CSRF pattern). These two auth flows never substitute
# for each other — see chat notes: submit needs JWT, poll needs Alto
# cookies, always both, in sequence, never a fallback from one to the other.
#
# SHARED BROWSER, SEPARATE PAGES PER DOMAIN:
# Alto is deployed separately per region behind different domains (sg, va,
# euttp, cn, oci-ttp — see header notes), each with its own cookie jar. This
# reuses the SAME persistent browser context as the JWT flow (_context —
# one visible window for the whole session) but keeps one tab per
# alto_domain in _alto_pages, since navigating a single shared tab between
# domains would lose whichever domain's cookies weren't active.
#
# WHY THIS STILL NEEDS THE BROWSER OPEN:
# Same reason the reboot/reinstall/recreate submits do — polling calls are
# executed as in-page fetch() via page.evaluate(), not Python requests, so
# cookies/CSRF are attached by the browser itself rather than us
# reconstructing them. The worker thread polling Alto needs this same
# browser window open and running for as long as anything is in-flight.
# ============================================================

_alto_pages = {}          # alto_domain -> Playwright page (one tab per domain)
_alto_csrf_tokens = {}    # alto_domain -> csrftoken cookie value


def _ensure_browser_context():
    """Bootstraps the shared persistent browser context if nothing has
    opened it yet (e.g. Alto polling starts before any reboot/reinstall/
    recreate has been submitted this session). Mirrors the launch block
    inside get_playwright_page() rather than calling it directly, since
    get_playwright_page() also does JWT-specific navigation/prompting that
    doesn't apply here."""
    global _browser, _context, _playwright
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("\nPlaywright is not installed. Run:")
        print("  pip install playwright")
        print("  playwright install chromium")
        sys.exit(1)

    if _playwright is None:
        _playwright = sync_playwright().start()
    if _context is None:
        _context = _launch_persistent_browser_context()
        _browser = _context


def get_alto_page(alto_domain: str, sample_ticket_url: str = "", prompt_label: str = "Alto page"):
    """Returns an authenticated page for the given alto_domain, reusing one
    tab per domain across calls. On first use for a domain, navigates there
    and waits for you to be logged in (cookies persist afterward, same as
    the JWT side, via the shared persistent browser profile).
    sample_ticket_url — pass the actual ticket_url for a real ticket on this
    domain when you have one (e.g. from pipeline state); it's a guaranteed-
    valid page to land on. Falls back to the bare domain root if omitted.
    """
    _ensure_browser_context()

    if alto_domain in _alto_pages:
        page = _alto_pages[alto_domain]
        # is_closed() is a local Playwright property check — no JS
        # round-trip, so it can't spuriously fail from a momentary
        # navigation/timing hiccup the way the old evaluate("() => true")
        # liveness probe could (which risked wrongly evicting a perfectly
        # good cached page and forcing a full re-prompt for no reason).
        if not page.is_closed():
            return page
        _alto_pages.pop(alto_domain, None)

    page = _context.new_page()
    _alto_pages[alto_domain] = page

    target_url = sample_ticket_url or f"https://{alto_domain}/"
    print(f"\nOpening {target_url}")
    print(f"→ If you are not logged in to Alto ({alto_domain}) yet, log in now.")
    print("→ The script will watch for the alto-authorization / csrftoken cookies.")
    try:
        page.goto(target_url, wait_until="domcontentloaded", timeout=60000)
    except Exception as e:
        print(f"  Navigation note: {e}")
        print("  (You can still log in manually in the open tab.)")

    def _capture_cookies() -> bool:
        try:
            cookies = _context.cookies([f"https://{alto_domain}"])
        except Exception:
            cookies = []
        found = {c["name"]: c["value"] for c in cookies}
        if "csrftoken" in found:
            _alto_csrf_tokens[alto_domain] = found["csrftoken"]
        # alto-authorization is the actual session cookie; csrftoken is what
        # we also need as a request header. Treat both present as "logged in".
        return "alto-authorization" in found and "csrftoken" in found

    # already_logged_in tracks whether this brand-new tab turned out to
    # already have valid session cookies (very common — the persistent
    # browser profile keeps cookies across runs/domains) without needing any
    # manual action. Used below to skip the redundant final "press ENTER"
    # prompt on a domain that's already authenticated. Before this fix
    # (2026-09-18), that final prompt fired unconditionally on every NEW
    # page (i.e. every new alto_domain encountered), even when login was
    # never actually needed — turning a poll pass across tickets filed on
    # several Alto shards into a forced manual pause per shard.
    already_logged_in = _capture_cookies()
    if not already_logged_in:
        input(f"\n>>> Finish Alto login for {alto_domain}, then press ENTER... ")
        for _ in range(20):
            if _capture_cookies():
                already_logged_in = True
                break
            time.sleep(0.5)

    if alto_domain in _alto_csrf_tokens:
        print(f"  Alto session cookies detected for {alto_domain}.")
    else:
        print(f"  Warning: alto-authorization/csrftoken not detected for {alto_domain}.")
        print("  Polling calls against this domain will likely fail until you log in.")

    if already_logged_in:
        print(f"  {prompt_label} already authenticated — skipping manual confirmation.")
    else:
        input(f"\n>>> Press ENTER after the {prompt_label} is ready... ")
    return page


def _alto_fetch(page, path_and_query: str) -> dict:
    """Runs a GET against Alto's API as an in-page fetch() — same pattern as
    the reboot/reinstall/recreate submits use for ie-oci, so cookies and the
    X-CSRF-Token header are attached exactly the way the real app would.
    path_and_query is relative (e.g. '/flow/api/v1/tickets/xxx/action?...'),
    resolved against whatever origin the page is currently on."""
    alto_domain = urlparse(page.url).netloc
    csrf = _alto_csrf_tokens.get(alto_domain, "")
    response = page.evaluate(
        """async ({path, csrf}) => {
            const res = await fetch(path, {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'accept': 'application/json',
                    'X-CSRF-Token': csrf
                }
            });
            const text = await res.text();
            return { status: res.status, body: text };
        }""",
        {"path": path_and_query, "csrf": csrf},
    )
    status = response.get("status")
    body_text = response.get("body", "")
    if status != 200:
        return {"_error": f"HTTP {status} from {url}", "_status": status, "_url": url, "_body": body_text[:300]}
    try:
        return json.loads(body_text)
    except json.JSONDecodeError:
        return {"_error": "bad JSON", "_body": body_text[:300]}


def alto_poll_action(page, ticket_id: str) -> dict:
    """GET /{ticket_id}/action — ticket + node states. See header notes:
    data.completed_at only reliably flips non-zero on SUCCESS, so don't use
    it alone as a settled check; the sub_tickets call below is what
    actually decides pass/fail."""
    return _alto_fetch(page, f"/flow/api/v1/tickets/{ticket_id}/action?identifier={ticket_id}")


def alto_get_sub_tickets(page, ticket_id: str, node_key: str) -> dict:
    """GET .../nodes/{node_key}/sub_tickets — the real child-ticket list;
    the true pass/fail source (see header notes: the parent's own
    top-level state can stay 'running' forever even after the real
    operation has already failed)."""
    return _alto_fetch(
        page,
        f"/flow/api/v1/tickets/{ticket_id}/nodes/{node_key}/sub_tickets"
        f"?identifier={ticket_id}&node_key={node_key}&page=1&page_size=10",
    )


def alto_get_variables(page, ticket_id: str) -> dict:
    """GET .../variables — input params, plus on a failed child ticket an
    operation-specific '*_detail' field with the raw underlying error."""
    return _alto_fetch(page, f"/flow/api/v1/tickets/{ticket_id}/variables?identifier={ticket_id}")


def _extract_alto_detail_field(variables_response: dict) -> str:
    """Scan an Alto /variables response for the first '*_detail' field.
    REAL SHAPE CONFIRMED 2026-09-14 (previous code assumed a flat dict,
    which is wrong): the actual variables live at
    data.ticket_variables.variables, a LIST of
    {"name": ..., "value": ..., "label": ...} objects — not a flat
    key->value dict. Matches on item['name'] ending in '_detail'. Keeps a
    flat-dict fallback afterward in case some other ticket/domain really
    does return that shape, but the list form is now the primary path."""
    if not isinstance(variables_response, dict) or "_error" in variables_response:
        return ""
    data = variables_response.get("data") or variables_response
    if not isinstance(data, dict):
        return ""

    var_list = (data.get("ticket_variables") or {}).get("variables")
    if isinstance(var_list, list):
        for item in var_list:
            if isinstance(item, dict) and str(item.get("name", "")).endswith("_detail") and item.get("value"):
                return str(item.get("value"))

    # Fallback: flat dict of key->value, in case a different shape shows up.
    for k, v in data.items():
        if str(k).endswith("_detail") and v:
            return str(v)
    return ""


def _find_alto_failure_events(histories_response: dict) -> list:
    """Scan an Alto /histories response for entries that look like an
    actual failure — category != 'state' (state-change entries are just
    ready/running/finished transitions, not failures), or a result/
    result_message/context containing 'fail'/'error', or a populated
    context.error_message. Returns the matching raw entries so they can
    be surfaced directly instead of relying on a truncated JSON dump to
    happen to include them."""
    if not isinstance(histories_response, dict) or "_error" in histories_response:
        return []
    data = histories_response.get("data") or histories_response
    entries = data.get("list") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return []

    matches = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        category = str(entry.get("category", ""))
        result = str(entry.get("result", ""))
        result_message = str(entry.get("result_message", ""))
        context = entry.get("context") or {}
        error_message = context.get("error_message") if isinstance(context, dict) else None
        haystack = f"{category} {result} {result_message}".lower()
        if error_message or "fail" in haystack or "error" in haystack:
            matches.append(entry)
    return matches


def alto_get_histories(page, ticket_id: str, page_size: int = 500) -> dict:
    """GET .../histories?page=1&page_size=N — append-only event log
    (category/result/result_message/context). Previously only a design
    note (never implemented) — added to check whether a failed *attempt*
    (e.g. a 'task_execution_failed' event) shows up here before the
    overall ticket state goes terminal, since a ticket can retry and sit
    at state='running' while an individual attempt already failed."""
    return _alto_fetch(
        page,
        f"/flow/api/v1/tickets/{ticket_id}/histories?identifier={ticket_id}&page=1&page_size={page_size}",
    )


# Known unrecoverable-failure signatures: patterns that mean a check
# genuinely can't succeed, no matter how many times Alto retries it —
# as opposed to a transient error retries might clear on their own.
# Per explicit design decision (2026-09-14): a reboot's ping/ssh check
# reporting CRITICAL is a real network-reachability failure, not
# something that self-heals on retry, so it should short-circuit
# straight to "failed" rather than waiting for the node/ticket to
# exhaust its retry budget and go terminal. Extend this list if other
# similarly-deterministic failure signatures turn up.
#
# Each entry is (key_fragment, value_fragment) rather than one glued
# string. Reasoning (2026-09-15): the original single-string patterns
# ("pingstatus:critical") only matched if the key and value were glued
# together with no separator in the source data. A normal parsed JSON
# key/value pair re-serialized via json.dumps() never looks like that —
# it's `"pingStatus": "CRITICAL"`, with a quote+colon+space between key
# and value. The glued-string patterns would silently never match that
# shape, meaning a real CRITICAL status could sit in the response text
# with the scan reporting "no match" and the ticket staying in
# "running" instead of escalating. The regex below matches key and
# value near each other regardless of the exact punctuation in between
# (quotes, colon, space, or "=") so it catches both a real JSON pair and
# the glued-string form, in case either turns up in practice.
ALTO_UNRECOVERABLE_FAILURE_PATTERNS = [
    (r"ping[\s_]*status", r"critical"),
    (r"ssh[\s_]*status", r"critical"),
]


def _scan_for_unrecoverable_failure(*api_responses) -> str:
    """Deep, structure-agnostic scan across one or more raw Alto API
    response dicts (e.g. whole /variables, /histories responses) for a
    known unrecoverable-failure signature. Structure-agnostic on purpose:
    as of 2026-09-14 we don't yet know which named field carries this
    while a ticket is still mid-retry (it may not be under a '*_detail'
    key at all pre-terminal), so this just stringifies each response and
    pattern-matches rather than assuming a field name. Returns a short
    text window around the first match (for a human-readable 'detail'),
    or "" if nothing matched.
    UNCONFIRMED (2026-09-15): this has not yet been validated against a
    real response that actually contains a CRITICAL status — if polling
    still doesn't escalate on a ticket you can SEE says CRITICAL, paste
    the raw /variables or /histories JSON (redact IDs/tokens as usual)
    so the pattern can be corrected against real data instead of guessed
    again.
    """
    for resp in api_responses:
        if not resp:
            continue
        try:
            blob = json.dumps(resp, ensure_ascii=False)
        except (TypeError, ValueError):
            continue
        lower = blob.lower()
        for key_frag, value_frag in ALTO_UNRECOVERABLE_FAILURE_PATTERNS:
            # key and value within ~40 chars of each other, in order,
            # covers a normal `"key": "value"` pair and close variants
            # (different quoting, "=" instead of ":", a nested field
            # separating them slightly) without needing exact punctuation.
            match = re.search(key_frag + r".{0,40}?" + value_frag, lower, re.DOTALL)
            if match:
                start = max(0, match.start() - 80)
                end = min(len(blob), match.end() + 80)
                return blob[start:end]
    return ""


def _check_alto_unrecoverable_failure(page, ticket_id: str) -> str:
    """Fetches this ticket's /variables and /histories fresh and scans
    both for an unrecoverable-failure signature. Returns the matched
    detail text, or "" if nothing matched (including on a fetch error —
    callers should treat "" as 'no unrecoverable signature seen yet',
    not as confirmation of health)."""
    variables = alto_get_variables(page, ticket_id)
    histories = alto_get_histories(page, ticket_id)
    return _scan_for_unrecoverable_failure(variables, histories)


def _alto_find_active_node_key(action_data: dict):
    """Best-effort scan of data.ticket_nodes[] for the call_activity node
    that's actually executing, as opposed to an untouched sibling branch of
    the same exclusive gateway (e.g. a 'close ticket' branch that never
    ran).
    Confirmed via a real captured /action response (2026-09-15): this API
    uses created_at/updated_at/completed_at timestamps on ticket_nodes —
    NOT start_time/started_at, which the original guess relied on and
    which are never present in real data. That meant this heuristic could
    never return a node_key at all before this fix — every poll fell back
    to checking the PARENT ticket's own /variables + /histories (process-
    level metadata only: ip_list, approvals, state changes), never the
    child sub-ticket where the actual per-host ping/ssh status lives. Kept
    start_time/started_at as a first choice in case a differently-shaped
    response ever provides them, but created_at/updated_at is now the
    fallback that actually fires against real data.
    """
    nodes = (action_data.get("data") or {}).get("ticket_nodes") or []
    for node in nodes:
        if node.get("node_type") != "call_activity":
            continue
        # Heuristic: a node that's actually run has a real (non-zero/
        # non-empty) start-type timestamp and/or a state that isn't just
        # "pending".
        started = (
            node.get("start_time") or node.get("started_at")
            or node.get("created_at") or node.get("updated_at") or 0
        )
        state = str(node.get("state", "")).lower()
        if started and state not in ("", "pending"):
            return node.get("node_key")
    return None


def alto_poll_ticket_status(page, ticket_id: str) -> dict:
    """High-level wrapper implementing the resolved pass/fail chain from
    the header notes:
      1. poll /action, find the actively-running call_activity node
      2. call that node's /sub_tickets — the REAL pass/fail source
      3. child state 'failed' -> pull '*_detail' from /variables
         child state 'finished' -> pass
         child state 'running'  -> keep polling
      user_task ('awaiting approval') is surfaced as its own state rather
      than being misread as stuck or as a failure.

    Returns: {"state": "running"|"finished"|"failed"|"awaiting_review"|"unknown",
              "detail": str, "child_ticket_id": str}
    NOTE: this is built directly from the reverse-engineering notes at the
    top of this file, some of which are flagged there as unconfirmed
    (multi-domain schema parity, exact *_detail field naming). Validate
    against a real in-flight ticket before trusting this for unattended
    escalation decisions.
    """
    action_data = alto_poll_action(page, ticket_id)
    if "_error" in action_data:
        return {"state": "unknown", "detail": f"action poll error: {action_data['_error']}", "child_ticket_id": ""}

    # Surface a pending human-approval user_task distinctly, per header
    # notes: high-risk (>=10 hosts) routes through a "Review" user_task
    # first. An unattended poller must not read this as stuck/failed.
    nodes = (action_data.get("data") or {}).get("ticket_nodes") or []
    for node in nodes:
        if node.get("node_type") == "user_task" and str(node.get("state", "")).lower() not in ("", "approved"):
            return {"state": "awaiting_review", "detail": "Alto user_task pending human approval", "child_ticket_id": ""}

    node_key = _alto_find_active_node_key(action_data)
    if not node_key:
        # No call_activity node to descend into. Normally this just means
        # the parent hasn't reached that step yet ("running" is correct).
        # But if ticket_id itself is actually a leaf/child ticket (e.g.
        # pasted directly for a manual deep-dive rather than a tracked
        # parent), it won't have any ticket_nodes of its own either, and
        # its OWN top-level state is the real answer — check that before
        # defaulting to "running", so a directly-pasted child ticket
        # doesn't get silently misreported.
        top_state = str((action_data.get("data") or {}).get("state", "")).lower()
        if top_state == "failed":
            variables = alto_get_variables(page, ticket_id)
            detail = _extract_alto_detail_field(variables)
            return {"state": "failed", "detail": detail or "failed (no *_detail field found)", "child_ticket_id": ticket_id}
        if top_state == "finished":
            return {"state": "finished", "detail": "", "child_ticket_id": ticket_id}
        # Top state is "running" (or unrecognized) — before accepting that,
        # check for an unrecoverable-failure signature (e.g. ping/ssh
        # CRITICAL) that retries can't fix. If present, treat this as
        # failed now rather than waiting out the retry/timeout window.
        unrecoverable = _check_alto_unrecoverable_failure(page, ticket_id)
        if unrecoverable:
            return {"state": "failed", "detail": unrecoverable, "child_ticket_id": ticket_id}
        return {"state": "running", "detail": "no active call_activity node found yet", "child_ticket_id": ""}

    sub_data = alto_get_sub_tickets(page, ticket_id, node_key)
    if "_error" in sub_data:
        return {"state": "unknown", "detail": f"sub_tickets error: {sub_data['_error']}", "child_ticket_id": ""}

    children = (sub_data.get("data") or {}).get("list") or sub_data.get("data") or []
    if isinstance(children, dict):
        children = [children]
    if not children:
        return {"state": "running", "detail": "no child tickets yet", "child_ticket_id": ""}

    # A parent can have multiple child tickets. A failure in any child is the
    # actionable outcome; report finished only after every child is finished.
    # Checking only children[0] can silently miss the real failed operation.
    normalized_children = []
    for child in children:
        child_id = child.get("uuid") or child.get("id") or ""
        child_state = str(child.get("state", "")).lower()
        normalized_children.append((child, child_id, child_state))

    for _, child_id, child_state in normalized_children:
        if child_state == "failed":
            variables = alto_get_variables(page, child_id) if child_id else {}
            detail = _extract_alto_detail_field(variables)
            return {
                "state": "failed",
                "detail": detail or "failed (no *_detail field found)",
                "child_ticket_id": child_id,
            }

    for _, child_id, child_state in normalized_children:
        if child_state not in ("finished", "failed"):
            unrecoverable = _check_alto_unrecoverable_failure(page, child_id) if child_id else ""
            if unrecoverable:
                return {"state": "failed", "detail": unrecoverable, "child_ticket_id": child_id}

    if normalized_children and all(state == "finished" for _, _, state in normalized_children):
        child_ids = ",".join(child_id for _, child_id, _ in normalized_children if child_id)
        return {"state": "finished", "detail": "", "child_ticket_id": child_ids}

    running_id = next(
        (child_id for _, child_id, state in normalized_children if state not in ("finished", "failed")),
        "",
    )
    return {"state": "running", "detail": "", "child_ticket_id": running_id}



# -------------------- shared helpers --------------------

def open_file(path: Path):
    try:
        system = platform.system()
        if system == "Darwin":
            subprocess.run(["open", str(path)], check=False)
        elif system == "Windows":
            subprocess.run(["start", "", str(path)], shell=True, check=False)
        else:
            subprocess.run(["xdg-open", str(path)], check=False)
    except Exception:
        pass


def find_latest_ticket_export(folder: Path = None) -> Path:
    folder = folder or Path.cwd()
    candidates = [
        p for p in folder.glob("*.xlsx")
        if not p.name.lower().startswith(("ssh_ping_action_queue", "ticketq_result", "reboot_result"))
    ]
    if not candidates:
        return None
    tickets = [p for p in candidates if p.name.lower().startswith("tickets")]
    if tickets:
        return max(tickets, key=lambda p: p.stat().st_mtime)
    return max(candidates, key=lambda p: p.stat().st_mtime)


def normalize_region(region: str) -> str:
    value = str(region or "").strip().lower().replace("-", "")
    aliases = {"i18n": "i18n", "euttp": "euttp", "eutt": "euttp", "both": "both"}
    if value not in aliases:
        raise ValueError(f"Unknown region {region!r}; expected I18N, EUTTP, or BOTH")
    return aliases[value]


def prompt_region() -> str:
    print("\nSelect ticket region:")
    print("  1) I18N")
    print("  2) EUTTP")
    print("  3) Both (one combined export and report, region-tagged rows)")
    choice = input("Region [1]: ").strip() or "1"
    try:
        return REGION_CHOICES[choice]
    except KeyError:
        raise ValueError("Invalid region choice; select 1, 2, or 3")


def infer_ticket_region(path: Path, df: pd.DataFrame = None) -> str:
    """Infer a workbook's region only from explicit local evidence."""
    if df is not None and "region" in df.columns:
        values = {str(value).strip().lower() for value in df["region"].dropna()}
        if values and values <= {"i18n", "euttp"}:
            return "both" if len(values) == 2 else next(iter(values))

    name = path.name.lower()
    if "euttp" in name or "eu-ttp" in name:
        return "euttp"
    if "i18n" in name:
        return "i18n"
    return ""


def find_latest_result(folder: Path = None) -> Path:
    folder = folder or Path.cwd()
    candidates = list(folder.glob("ticketq_result_*.xlsx"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


# -------------------- ticketq logic --------------------

def load_tickets(path: Path) -> pd.DataFrame:
    xls = pd.ExcelFile(path)
    if "Tickets" in xls.sheet_names:
        return pd.read_excel(xls, sheet_name="Tickets")
    for sheet in xls.sheet_names:
        df = pd.read_excel(xls, sheet_name=sheet)
        if not df.empty:
            return df
    raise ValueError("No non-empty sheet found")


def _detail_keyword_mask(df: pd.DataFrame, keywords: list) -> pd.Series:
    """Case-insensitive substring match of `detail` against a keyword list.
    Returns an all-False mask if there's no `detail` column or no keywords,
    so callers never need to special-case an empty list."""
    if not keywords or "detail" not in df.columns:
        return pd.Series(False, index=df.index)
    pattern = "|".join(re.escape(k) for k in keywords)
    return df["detail"].astype(str).str.contains(pattern, case=False, na=False)


def apply_filters(df: pd.DataFrame, show_excluded: bool = False) -> pd.DataFrame:
    type_mask = df["type"].astype(str).str.contains(r"ping|ssh", case=False, na=False)
    # See INCLUDE_DETAIL_KEYWORDS / RECREATE_DETAIL_KEYWORDS / DISK_LOST_DETAIL_KEYWORDS
    # / NVME_TIMEOUT_RESET_DETAIL_KEYWORDS in CONFIG above to add new ticket
    # types by `detail` text instead of `type`.
    detail_mask = (
        _detail_keyword_mask(df, INCLUDE_DETAIL_KEYWORDS)
        | _detail_keyword_mask(df, RECREATE_DETAIL_KEYWORDS)
        | _detail_keyword_mask(df, DISK_LOST_DETAIL_KEYWORDS)
        | _detail_keyword_mask(df, DUAL_IP_DETAIL_KEYWORDS)
        | _detail_keyword_mask(df, NVME_TIMEOUT_RESET_DETAIL_KEYWORDS)
    )
    mask = type_mask | detail_mask
    if show_excluded:
        print(f"  Type filter (Ping/SSH): {type_mask.sum()} / {len(df)}")
        print(f"  Detail-keyword filter : {detail_mask.sum()} / {len(df)}")
        print(f"  Combined intake filter: kept {mask.sum()} / {len(df)}")
    work = df.loc[mask].copy()

    if "product" in work.columns:
        prod_pattern = "|".join(re.escape(str(x)) for x in EXCLUDE_PRODUCT_KEYWORDS)
        prod_mask = ~work["product"].astype(str).str.contains(prod_pattern, case=False, na=False)
        if show_excluded:
            print(f"  Product filter: kept {prod_mask.sum()} / {len(work)}")
        work = work.loc[prod_mask]

    if "operator_name" in work.columns:
        op_pattern = "|".join(re.escape(str(x)) for x in EXCLUDE_OPERATORS)
        op_mask = ~work["operator_name"].astype(str).str.contains(op_pattern, case=False, na=False)
        if show_excluded:
            print(f"  Operator filter: kept {op_mask.sum()} / {len(work)}")
        work = work.loc[op_mask]

    psm_cols = [c for c in ["request_psm_name", "allow_psm_name", "not_allow_psm_name"] if c in work.columns]
    if psm_cols:
        psm_pattern = "|".join(re.escape(str(x)) for x in EXCLUDE_PSM_KEYWORDS)
        psm_mask = pd.Series(True, index=work.index)
        for col in psm_cols:
            psm_mask &= ~work[col].astype(str).str.contains(psm_pattern, case=False, na=False)
        if show_excluded:
            print(f"  PSM filter: kept {psm_mask.sum()} / {len(work)}")
        work = work.loc[psm_mask]

    return work


def enrich(work: pd.DataFrame) -> pd.DataFrame:
    if "ipv4" in work.columns and "ip" in work.columns:
        work["check_ip"] = work["ipv4"].fillna(work["ip"])
    elif "ip" in work.columns:
        work["check_ip"] = work["ip"]
    else:
        work["check_ip"] = ""

    work["recommended_next_step"] = "1. Check port 22 reachability"
    work["port22_result"] = ""
    work["status"] = "Pending port-22 check"
    work["action_taken"] = ""
    work["result"] = ""
    work["notes"] = ""

    if "id" in work.columns:
        def ticket_link(row):
            if pd.isna(row.get("id")):
                return ""
            host = "fault.tiktok-eu.net" if str(row.get("region", "")).lower() == "euttp" else "fault-i18n.tiktok-row.net"
            return f"https://{host}/fault/{row['id']}"

        work["link"] = work.apply(ticket_link, axis=1)
    else:
        work["link"] = ""

    preferred = [
        "id", "type", "detail", "check_ip", "port22_result",
        "ipv4", "ipv6", "sn", "host_sn",
        "product", "link", "product_line", "operator_name", "created",
        "recommended_next_step", "status", "action_taken", "result", "notes",
        "progress", "request_psm_name", "allow_psm_name", "not_allow_psm_name",
    ]
    cols = [c for c in preferred if c in work.columns]
    extra = [c for c in work.columns if c not in cols]
    work = work[cols + extra]

    if "created" in work.columns:
        work = work.sort_values("created", ascending=False)
    return work.reset_index(drop=True)


def run_port22_checks(ip_list: list, region: str = "i18n") -> dict:
    region = normalize_region(region)
    if region == "both":
        raise ValueError("run_port22_checks() accepts one region at a time")
    config = REGION_CONFIG[region]
    results = {}
    unique_ips = list(dict.fromkeys([ip for ip in ip_list if ip and str(ip).strip()]))
    print(f"\nPreparing to check {len(unique_ips)} unique {config['label']} IPs on port 22...")

    page = get_playwright_page(config["port_page"], prompt_label=f"{config['label']} port-test page")
    page_jwt = _page_jwt_headers(page)
    jwt_value = page_jwt.get("X-Jwt-Token", "")

    try:
        for i in range(0, len(unique_ips), PORT_BATCH_SIZE):
            batch = unique_ips[i:i + PORT_BATCH_SIZE]
            print(f"  Checking batch {i // PORT_BATCH_SIZE + 1} ({len(batch)} IPs)...")

            payload = {"op_type": "22port", "ip_list": batch, "ip_type": ""}

            try:
                response = page.evaluate(
                    """async ({url, targetUrl, payload, mode, jwt}) => {
                        const directHeaders = {
                            'Content-Type': 'application/json; charset=utf-8',
                            'accept': 'application/json',
                            'accept-language': 'en'
                        };
                        const request = mode === 'ttp_proxy'
                            ? {
                                url: targetUrl,
                                header: 'e30=',
                                method: 'POST',
                                body: btoa(JSON.stringify(payload))
                            }
                            : null;
                        const res = await fetch(url, {
                            method: 'POST',
                                headers: mode === 'ttp_proxy'
                                ? {'accept': 'application/json', 'content-type': 'application/json; charset=UTF-8', 'x-jwt-token': jwt}
                                : directHeaders,
                            body: mode === 'ttp_proxy' ? JSON.stringify(request) : JSON.stringify(payload),
                            credentials: mode === 'ttp_proxy' ? 'omit' : 'include'
                        });
                        const text = await res.text();
                        return { status: res.status, body: text };
                    }""",
                    {
                        "url": config["port_api"],
                        "targetUrl": config.get("port_target_api", ""),
                        "payload": payload,
                        "mode": config["port_mode"],
                        "jwt": jwt_value,
                    }
                )

                status = response.get("status")
                body_text = response.get("body", "")

                if status != 200:
                    print(f"    API returned HTTP {status}")
                    print(f"    Body: {body_text[:300]}")
                    print("\n*** Stopping on first error ***")
                    for ip in batch:
                        results[ip] = f"Error: HTTP {status}"
                    break

                try:
                    data = json.loads(body_text)
                except json.JSONDecodeError:
                    print(f"    Could not parse JSON: {body_text[:300]}")
                    print("\n*** Stopping on first error ***")
                    for ip in batch:
                        results[ip] = "Error: bad JSON"
                    break

                # ttp_proxy responses arrive double-wrapped: the outer body
                # is {"base64": true, "data": "<base64-encoded-JSON>"} — the
                # REAL {"status"/"code"/"result"} payload is base64 inside
                # "data". Confirmed via a real captured response (2026-09-15).
                # This has NOTHING to do with domains — even with perfect
                # config["port_api"]/port_target_api values, parsing would
                # have failed here every time without this unwrap step.
                if config["port_mode"] == "ttp_proxy" and isinstance(data, dict) and data.get("base64"):
                    try:
                        inner_text = base64.b64decode(data.get("data", "")).decode("utf-8")
                        data = json.loads(inner_text)
                    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
                        print(f"    Could not unwrap ttp_proxy base64 envelope: {e}")
                        print(f"    Raw body: {body_text[:300]}")
                        print("\n*** Stopping on first error ***")
                        for ip in batch:
                            results[ip] = "Error: bad ttp_proxy envelope"
                        break

                if i == 0:
                    print("    Sample API response structure:")
                    print(json.dumps(data, indent=2, ensure_ascii=False)[:800])

                parsed = False
                if isinstance(data, dict) and "result" in data:
                    result = data["result"]
                    if isinstance(result, dict):
                        for ip in result.get("succeed", []) or []:
                            results[str(ip)] = "Reachable"
                        for ip in result.get("failed", []) or []:
                            results[str(ip)] = "Unreachable"
                        for ip in result.get("success", []) or []:
                            results[str(ip)] = "Reachable"
                        parsed = True

                if not parsed:
                    print("    Warning: could not understand response structure.")
                    print(body_text[:500])
                    print("\n*** Stopping on first error ***")
                    for ip in batch:
                        results[ip] = "Error: unknown response format"
                    break

            except Exception as e:
                print(f"    Exception during batch: {e}")
                print("\n*** Stopping on first error ***")
                for ip in batch:
                    results[ip] = f"Error: {e}"
                break

            time.sleep(0.8)

    except Exception as e:
        print(f"Port-22 check error: {e}")
        raise

    print("\n(Browser left open for reuse. It will close when you exit the dashboard.)")
    return results


def build_ticketq_workbook(work: pd.DataFrame, source_name: str, total_source: int) -> Workbook:
    wb = Workbook()
    header_fill = PatternFill("solid", fgColor="1F4E79")
    header_font = Font(bold=True, color="FFFFFF")
    thin = Border(
        left=Side(style="thin"), right=Side(style="thin"),
        top=Side(style="thin"), bottom=Side(style="thin"),
    )
    ssh_fill = PatternFill("solid", fgColor="FCE4D6")
    ping_fill = PatternFill("solid", fgColor="DDEBF7")
    reachable_fill = PatternFill("solid", fgColor="C6EFCE")
    unreachable_fill = PatternFill("solid", fgColor="FFC7CE")

    ws = wb.active
    ws.title = "Action Queue"

    for col_idx, col_name in enumerate(work.columns, 1):
        cell = ws.cell(row=1, column=col_idx, value=col_name)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", wrap_text=True)
        cell.border = thin

    for row_idx, row in enumerate(work.itertuples(index=False), 2):
        for col_idx, value in enumerate(row, 1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.border = thin
            cell.alignment = Alignment(wrap_text=True, vertical="center")

        type_val = str(row[work.columns.get_loc("type")]).lower() if "type" in work.columns else ""
        base_fill = ssh_fill if "ssh" in type_val else ping_fill
        for c in range(1, len(work.columns) + 1):
            ws.cell(row=row_idx, column=c).fill = base_fill

        if "port22_result" in work.columns:
            res_col = work.columns.get_loc("port22_result") + 1
            res_val = str(row[work.columns.get_loc("port22_result")]).lower()
            cell = ws.cell(row=row_idx, column=res_col)
            if "reachable" in res_val and "un" not in res_val:
                cell.fill = reachable_fill
            elif "unreachable" in res_val:
                cell.fill = unreachable_fill

    widths = {
        "id": 12, "type": 10, "detail": 34, "check_ip": 22, "port22_result": 14,
        "ipv4": 16, "ipv6": 40, "sn": 50, "host_sn": 16, "product": 26, "link": 42,
        "product_line": 12, "operator_name": 16, "created": 18,
        "recommended_next_step": 26, "status": 20, "action_taken": 16,
        "result": 14, "notes": 20, "progress": 14,
    }
    for col_idx, col_name in enumerate(work.columns, 1):
        ws.column_dimensions[get_column_letter(col_idx)].width = widths.get(col_name, 14)

    ws.auto_filter.ref = ws.dimensions
    ws.freeze_panes = "A2"

    ws2 = wb.create_sheet("Summary")
    ws2["A1"] = "SSH / Ping Action Queue + Port-22 Results"
    ws2["A1"].font = Font(bold=True, size=14)
    ws2["A2"] = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    ws2["A3"] = f"Source: {source_name}"
    ws2["A4"] = f"Total tickets in source: {total_source}"
    ws2["A5"] = f"After filters: {len(work)}"
    if "port22_result" in work.columns:
        counts = work["port22_result"].value_counts()
        ws2["A7"] = "Port-22 results"
        ws2["A7"].font = Font(bold=True)
        for i, (k, v) in enumerate(counts.items(), 8):
            ws2[f"A{i}"] = k
            ws2[f"B{i}"] = v
    ws2.column_dimensions["A"].width = 40
    ws2.column_dimensions["B"].width = 12

    ws3 = wb.create_sheet("Raw Filtered")
    for r_idx, row in enumerate(dataframe_to_rows(work, index=False, header=True), 1):
        for c_idx, value in enumerate(row, 1):
            ws3.cell(row=r_idx, column=c_idx, value=value)
    ws3.auto_filter.ref = ws3.dimensions
    ws3.freeze_panes = "A2"

    return wb


def do_ticketq(skip_check: bool = False, auto_export: bool = False, region: str = ""):
    if auto_export:
        selected_region = normalize_region(region or prompt_region())
        if selected_region == "both":
            frames = []
            for one_region in ("i18n", "euttp"):
                one_path = export_tickets_from_web(one_region)
                one_df = load_tickets(one_path)
                one_df["region"] = REGION_CONFIG[one_region]["label"]
                frames.append(one_df)
            df = pd.concat(frames, ignore_index=True, sort=False)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = Path.cwd() / f"Tickets_BOTH_export_{ts}.xlsx"
            df.to_excel(path, index=False, sheet_name="Tickets")
            region = selected_region
        else:
            region = selected_region
            path = export_tickets_from_web(selected_region)
            df = load_tickets(path)
            df["region"] = REGION_CONFIG[region]["label"]
    else:
        path = find_latest_ticket_export()
        if path is None:
            print("No Excel file found. Put a Tickets*.xlsx in this folder.")
            return
        df = load_tickets(path)
        # A manually-provided file has NO auto_export signal to tell us its
        # region — infer from real evidence (an existing `region` column,
        # or "i18n"/"euttp" in the filename) and only ask as a last resort.
        # Silently defaulting here was the original i18n-hardcode bug: a
        # manually-exported eu-ttp file would get port-22-checked against
        # i18n's site with no warning.
        inferred = infer_ticket_region(path, df)
        if inferred:
            region = inferred
            source = "the region column" if "region" in df.columns else "the filename"
            label = REGION_CONFIG.get(region, {}).get("label", region)
            print(f"  Detected region: {label} (from {source})")
        else:
            print("  Could not tell which region this file is from "
                  "(no `region` column, filename doesn't say i18n/euttp).")
            region = normalize_region(prompt_region())
            if region == "both":
                print("  A single file can't be tagged 'both' — pick I18N or EUTTP.")
                return
        if region in REGION_CONFIG and "region" not in df.columns:
            df["region"] = REGION_CONFIG[region]["label"]

    print("\n========================================")
    print(f"  Excel file : {path.name}")
    print(f"  Full path  : {path}")
    print("========================================\n")

    print(f"  Total rows: {len(df)}")

    work = apply_filters(df, show_excluded=True)
    print(f"  After filters: {len(work)}")

    if work.empty:
        print("No tickets left after filtering.")
        return

    filesystem_mask = _detail_keyword_mask(work, FILESYSTEM_DETAIL_KEYWORDS)
    filesystem_work = work.loc[filesystem_mask].copy()
    work = work.loc[~filesystem_mask].copy()

    if not filesystem_work.empty:
        filesystem_work = enrich(filesystem_work)
        filesystem_work["recommended_next_step"] = "Manual filesystem investigation"
        filesystem_work["status"] = "Filesystem ticket - do not reboot"
        filesystem_work["port22_result"] = "N/A (Filesystem)"
        filesystem_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filesystem_out = path.parent / f"filesystem_tickets_{filesystem_ts}.xlsx"
        filesystem_wb = build_ticketq_workbook(
            filesystem_work,
            path.name,
            len(filesystem_work),
        )
        filesystem_wb.save(filesystem_out)
        print(f"\nSaved filesystem tickets separately: {filesystem_out}")
        open_file(filesystem_out)
        print("Filesystem tickets were excluded from the reboot/port-22 queue.")

    # OS EIPv4 + EIPv6 unreachable tickets get a dedicated workflow. Keep
    # them out of the generic port-22/reboot queue because their correct
    # diagnostic path first resolves OCI secondary addresses, then checks
    # those addresses on SAOS, then uses the captured Aries NIC-state check.
    dual_ip_mask = _detail_keyword_mask(work, DUAL_IP_DETAIL_KEYWORDS)
    dual_ip_work = work.loc[dual_ip_mask].copy()
    work = work.loc[~dual_ip_mask].copy()

    if not dual_ip_work.empty:
        dual_ip_work = enrich(dual_ip_work)
        dual_ip_work["recommended_next_step"] = (
            "Option N: OCI IPv6 instance lookup -> secondary IPv4/IPv6 SAOS "
            "port-22 check -> Aries NIC state if both unreachable -> "
            "Recreate on NO-CARRIER, otherwise Reinstall + post-check -> Recreate if still unreachable"
        )
        dual_ip_work["status"] = "Dual-IP unreachable - dedicated workflow (menu N)"
        dual_ip_work["port22_result"] = "N/A (Dual-IP workflow)"
        dual_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dual_out = path.parent / f"dual_ip_tickets_{dual_ts}.xlsx"
        dual_wb = build_ticketq_workbook(dual_ip_work, path.name, len(dual_ip_work))
        dual_wb.save(dual_out)
        print(f"\nSaved OS EIPv4/EIPv6 unreachable tickets separately: {dual_out}")
        open_file(dual_out)
        print("OS EIPv4/EIPv6 unreachable tickets were excluded from the generic port-22 queue (run menu N).")

    # Disk/NVMe-lost tickets (see DISK_LOST_DETAIL_KEYWORDS in CONFIG for the
    # intended maintenance-check/Aries process — NOT automated yet, this
    # only detects and separates them for manual handling in the meantime).
    disk_lost_mask = _detail_keyword_mask(work, DISK_LOST_DETAIL_KEYWORDS)
    disk_lost_work = work.loc[disk_lost_mask].copy()
    work = work.loc[~disk_lost_mask].copy()

    if not disk_lost_work.empty:
        disk_lost_work = enrich(disk_lost_work)
        disk_lost_work["recommended_next_step"] = (
            "1. Check maintenance_event on ie-oci batch_query — if SCHEDULED, "
            "start Recreate. 2. If not, run the Aries check "
            "(https://aries.tiktok-row.org/modification/modificationList/launch"
            "?maintainer=edwinlim.rciw) and follow its output. (Not yet automated.)"
        )
        disk_lost_work["status"] = "Disk/NVMe lost - maintenance check pending (manual, not yet automated)"
        disk_lost_work["port22_result"] = "N/A (Disk/NVMe lost)"
        disk_lost_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        disk_lost_out = path.parent / f"disk_lost_tickets_{disk_lost_ts}.xlsx"
        disk_lost_wb = build_ticketq_workbook(
            disk_lost_work,
            path.name,
            len(disk_lost_work),
        )
        disk_lost_wb.save(disk_lost_out)
        print(f"\nSaved disk/NVMe-lost tickets separately: {disk_lost_out}")
        open_file(disk_lost_out)
        print("Disk/NVMe-lost tickets were excluded from the reboot/port-22 queue "
              "(maintenance check + Aries step still manual — see DISK_LOST_DETAIL_KEYWORDS).")

    # NVMe QID-timeout/reset-controller tickets get their own dedicated
    # workflow (menu option — see NVME_TIMEOUT_RESET_DETAIL_KEYWORDS): same
    # Aries "check NVMEs" script as disk-lost above, but with a 660s deploy
    # timeout, then auto-routed by outcome (agent_lost -> Recreate, other
    # failure -> OCI SR, pass -> Reinstall + verify).
    nvme_timeout_mask = _detail_keyword_mask(work, NVME_TIMEOUT_RESET_DETAIL_KEYWORDS)
    nvme_timeout_work = work.loc[nvme_timeout_mask].copy()
    work = work.loc[~nvme_timeout_mask].copy()

    if not nvme_timeout_work.empty:
        nvme_timeout_work = enrich(nvme_timeout_work)
        nvme_timeout_work["recommended_next_step"] = (
            "Run the NVMe timeout/reset workflow: Aries 'check NVMEs' with a "
            "660s deploy timeout, then agent_lost -> Recreate / other failure "
            "-> OCI SR / pass -> Reinstall + verify."
        )
        nvme_timeout_work["status"] = "NVMe QID timeout/reset - dedicated workflow"
        nvme_timeout_work["port22_result"] = "N/A (NVMe timeout/reset workflow)"
        nvme_timeout_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        nvme_timeout_out = path.parent / f"nvme_timeout_reset_tickets_{nvme_timeout_ts}.xlsx"
        nvme_timeout_wb = build_ticketq_workbook(
            nvme_timeout_work,
            path.name,
            len(nvme_timeout_work),
        )
        nvme_timeout_wb.save(nvme_timeout_out)
        print(f"\nSaved NVMe timeout/reset tickets separately: {nvme_timeout_out}")
        open_file(nvme_timeout_out)
        print("NVMe timeout/reset tickets were excluded from the reboot/port-22 queue "
              "(run the dedicated NVMe timeout/reset workflow).")

    if work.empty:
        print("No remaining tickets left after filtering.")
        return

    work = enrich(work)

    # Tag "Recreate candidate" rows by `detail` text (see RECREATE_DETAIL_KEYWORDS
    # in CONFIG). These skip the port-22 check below — reachability isn't the
    # signal for a degraded/alarmed host — and are picked up later by menu
    # option 8/9 (do_recreate_from_tickets), which reads them back out of the
    # "Action Queue" sheet by their status value.
    recreate_mask = _detail_keyword_mask(work, RECREATE_DETAIL_KEYWORDS)
    work.loc[recreate_mask, "recommended_next_step"] = "Recreate (menu option 8/9)"
    work.loc[recreate_mask, "status"] = "Recreate candidate"
    if show := recreate_mask.sum():
        print(f"  Recreate candidates (skipping port-22 check for these): {show}")

    if not skip_check:
        check_mask = ~recreate_mask
        results = {}
        if "region" in work.columns:
            for row_region, rows in work.loc[check_mask].groupby("region"):
                region_key = normalize_region(row_region)
                ip_list = rows["check_ip"].dropna().astype(str).tolist()
                results.update(run_port22_checks(ip_list, region=region_key))
        else:
            ip_list = work.loc[check_mask, "check_ip"].dropna().astype(str).tolist()
            results = run_port22_checks(ip_list)
        work.loc[check_mask, "port22_result"] = work.loc[check_mask, "check_ip"].map(
            lambda ip: results.get(str(ip), "Not checked")
        )
        work.loc[recreate_mask, "port22_result"] = "N/A (Recreate)"
        work.loc[check_mask & (work["port22_result"] == "Reachable"), "status"] = "Reachable – verify & close"
        work.loc[check_mask & (work["port22_result"] == "Unreachable"), "status"] = "Unreachable – consider reboot"
    else:
        print("Skipping port-22 checks")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = path.parent / f"ticketq_result_{ts}.xlsx"
    wb = build_ticketq_workbook(work, path.name, len(df))
    wb.save(out)
    print(f"\nSaved: {out}")
    open_file(out)
    print("Done.")


# -------------------- rebootq logic --------------------

def load_unreachable(path: Path) -> pd.DataFrame:
    df = pd.read_excel(path, sheet_name="Action Queue")
    if "port22_result" not in df.columns:
        raise ValueError("No port22_result column. Run ticketq first.")
    mask = df["port22_result"].astype(str).str.strip().str.lower() == "unreachable"
    work = df.loc[mask].copy()
    if "check_ip" not in work.columns:
        raise ValueError("No check_ip column found.")
    work = work[work["check_ip"].notna() & (work["check_ip"].astype(str).str.strip() != "")]
    return work.reset_index(drop=True)


def load_recreate_candidates(path: Path) -> pd.DataFrame:
    """Pulls rows tagged status == 'Recreate candidate' by do_ticketq's
    RECREATE_DETAIL_KEYWORDS matching (see CONFIG at top of file)."""
    df = pd.read_excel(path, sheet_name="Action Queue")
    if "status" not in df.columns:
        raise ValueError("No status column. Run ticketq (option 1 or 6) first.")
    mask = df["status"].astype(str).str.strip().str.lower() == "recreate candidate"
    work = df.loc[mask].copy()
    if "check_ip" not in work.columns:
        raise ValueError("No check_ip column found.")
    work = work[work["check_ip"].notna() & (work["check_ip"].astype(str).str.strip() != "")]
    return work.reset_index(drop=True)


def _run_operation_per_ip(ip_list: list, dry_run: bool, *, action: str, page_url: str,
                           confirm_word: str, label: str, verb: str,
                           extra_payload: dict = None, confirm: bool = True) -> dict:
    """Shared per-IP submit loop for any /api/resource/operate?action=<action> call
    (Reboot, Reinstall, ...). Submits one IP per request rather than batching, since
    some backends silently reject batches that mix IPs from different PSMs.
    """
    results = {}
    unique_ips = list(dict.fromkeys([str(ip).strip() for ip in ip_list if ip]))
    extra_payload = extra_payload or {}

    print(f"\nIPs that will be {label} ({len(unique_ips)}):")
    for i, ip in enumerate(unique_ips, 1):
        print(f"  {i:3d}. {ip}")
    print()

    if dry_run:
        print("[DRY-RUN] No API calls will be made.")
        for ip in unique_ips:
            results[ip] = {"status": "Dry-run", "message": "Skipped", "ticketId": "", "ticketUrl": ""}
        return results

    if confirm:
        confirmation = input(f"Type {confirm_word} (all caps) to continue, or anything else to cancel: ").strip()
        if confirmation != confirm_word:
            print("Cancelled.")
            return results

    page = get_playwright_page(page_url, prompt_label=f"{action} page")

    print(f"  Waiting for the {action} page to establish its authenticated session...")
    # Do not manufacture/clone JWTs. Wait for the browser to observe the same
    # X-Jwt-Token-* headers that the real web application sends.
    import time
    deadline = time.time() + 30
    while time.time() < deadline and not _sanitize_jwt_map(_captured_jwt_headers):
        try:
            page_tokens = page.evaluate("() => window.__capturedJwtHeaders || {}")
            if isinstance(page_tokens, dict):
                for k, v in page_tokens.items():
                    if v and str(v).startswith("eyJ") and str(v).count(".") == 2:
                        _captured_jwt_headers[str(k)] = str(v)
        except Exception:
            pass
        time.sleep(0.5)
    if _captured_jwt_headers:
        print(f"  Authentication detected: {list(_captured_jwt_headers.keys())}")
    else:
        print(f"  Warning: no JWT headers observed yet; the first {action.lower()} request may fail if the session is not authenticated.")

    print(f"\n  Submitting each IP individually ({len(unique_ips)} total) — some backends reject")
    print("  mixed-PSM batches, so each IP gets its own request and its own result.\n")

    consecutive_jwt_failures = 0

    try:
        for idx, ip in enumerate(unique_ips, 1):
            print(f"  [{idx}/{len(unique_ips)}] {verb} {ip} ...")

            payload = {"ips": [ip], **extra_payload}

            try:
                # Also pull latest from page right before the call
                try:
                    page_tokens = page.evaluate("() => window.__capturedJwtHeaders || {}")
                    if isinstance(page_tokens, dict):
                        _captured_jwt_headers.update(page_tokens)
                except Exception:
                    pass

                captured_clean = _sanitize_jwt_map(_captured_jwt_headers)

                if not captured_clean:
                    # Tokens are short-lived (~1hr) and this may be well into a long
                    # run — reload the page once to force the site to issue fresh
                    # ones, rather than failing immediately on an expired token.
                    print("    No live JWT on hand (expired or not yet captured) — reloading page to refresh...")
                    try:
                        page.reload(wait_until="domcontentloaded", timeout=30000)
                    except Exception as e:
                        print(f"    Reload failed: {e}")
                    reload_deadline = time.time() + 15
                    while time.time() < reload_deadline and not _sanitize_jwt_map(_captured_jwt_headers):
                        try:
                            page_tokens = page.evaluate("() => window.__capturedJwtHeaders || {}")
                            if isinstance(page_tokens, dict):
                                for k, v in page_tokens.items():
                                    if v and str(v).startswith("eyJ") and str(v).count(".") == 2:
                                        _captured_jwt_headers[str(k)] = str(v)
                        except Exception:
                            pass
                        time.sleep(0.5)
                    captured_clean = _sanitize_jwt_map(_captured_jwt_headers)

                if captured_clean:
                    consecutive_jwt_failures = 0
                    sample = captured_clean.get("X-Jwt-Token") or next(iter(captured_clean.values()))
                    parts = sample.split(".")
                    exp = _jwt_exp(sample)
                    exp_str = f", exp_in={int(exp - time.time())}s" if exp else ""
                    print(f"    Using JWT: length={len(sample)}, segments={len(parts)}, part_lens={[len(p) for p in parts]}, prefix={sample[:22]}...{exp_str}")
                else:
                    consecutive_jwt_failures += 1
                    print("    ERROR: no valid, non-expired JWT available to send (even after reload).")
                    print(f"    Raw captured keys: {list(_captured_jwt_headers.keys())}")
                    for k, v in list(_captured_jwt_headers.items())[:5]:
                        vs = str(v)[:40] if v else ""
                        print(f"      {k}: len={len(str(v) if v else 0)}, segments={str(v).count('.')+1 if v else 0}, start={vs!r}")
                    print(f"    Tip: make sure you're logged in and the {action} page is fully loaded.")
                    results[ip] = {"status": "Error: no valid JWT", "message": "no valid JWT", "ticketId": "", "ticketUrl": ""}
                    if consecutive_jwt_failures >= 3:
                        print("\n*** 3 consecutive auth failures — this looks like a real auth problem, not a per-IP one. Stopping. ***")
                        for remaining_ip in unique_ips[idx:]:
                            results[remaining_ip] = {"status": "Skipped", "message": "Stopped after repeated auth failures", "ticketId": "", "ticketUrl": ""}
                        break
                    time.sleep(1.0)
                    continue

                response = page.evaluate(
                    """async (args) => {
                        const payload = args.payload;
                        const action = args.action;
                        const captured = args.captured || {};
                        // Valid JWT = exactly 3 base64 segments separated by dots
                        function isValidJwt(v) {
                            if (!v || typeof v !== 'string') return false;
                            const s = v.trim();
                            if (!s.startsWith('eyJ')) return false;
                            const parts = s.split('.');
                            return parts.length === 3 && parts.every(p => p.length > 0);
                        }

                        function collectTokens() {
                            const tokens = {};
                            function consider(k, v) {
                                if (!v || typeof v !== 'string') return;
                                let val = v.trim();
                                // sometimes stored as JSON string
                                if (val.startsWith('"') && val.endsWith('"')) {
                                    try { val = JSON.parse(val); } catch (e) {}
                                }
                                if (isValidJwt(val)) tokens[k] = val;
                            }
                            try {
                                for (let i = 0; i < localStorage.length; i++) {
                                    const k = localStorage.key(i);
                                    consider(k, localStorage.getItem(k));
                                }
                            } catch (e) {}
                            try {
                                for (let i = 0; i < sessionStorage.length; i++) {
                                    const k = sessionStorage.key(i);
                                    consider(k, sessionStorage.getItem(k));
                                }
                            } catch (e) {}
                            try {
                                document.cookie.split(';').forEach(c => {
                                    const [k, ...rest] = c.trim().split('=');
                                    try { consider(k, decodeURIComponent(rest.join('='))); } catch (e) {}
                                });
                            } catch (e) {}
                            try {
                                if (window.__JWT__) consider('X-Jwt-Token', window.__JWT__);
                                if (window.jwtToken) consider('X-Jwt-Token', window.jwtToken);
                            } catch (e) {}
                            return tokens;
                        }

                        const tokens = collectTokens();
                        const headers = {
                            'Content-Type': 'application/json',
                            'Accept': 'application/json, text/plain, */*'
                        };

                        // Prefer the exact header/token pairs observed in real browser
                        // traffic. Do not clone one JWT into another header name.
                        let mainJwt = null;
                        for (const [k, v] of Object.entries(captured)) {
                            if (isValidJwt(v) && k.toLowerCase().startsWith('x-jwt-token')) {
                                headers[k] = v;
                                if (k.toLowerCase() === 'x-jwt-token') mainJwt = v;
                            }
                        }
                        // If no captured primary header exists, use storage only as a
                        // last-resort X-Jwt-Token source.
                        if (!mainJwt) {
                            for (const [k, v] of Object.entries(tokens)) {
                                if (isValidJwt(v)) { mainJwt = v; break; }
                            }
                            if (mainJwt) headers['X-Jwt-Token'] = mainJwt;
                        }

                        const res = await fetch('/api/resource/operate?action=' + encodeURIComponent(action), {
                            method: 'POST',
                            headers,
                            body: JSON.stringify(payload)
                        });
                        const text = await res.text();
                        return {
                            status: res.status,
                            body: text,
                            tokenFound: !!mainJwt || Object.keys(captured).length > 0,
                            tokenKeys: Object.keys(tokens).concat(Object.keys(captured))
                        };
                    }""",
                    {"payload": payload, "captured": captured_clean, "action": action}
                )

                status = response.get("status")
                body_text = response.get("body", "")
                if not response.get("tokenFound"):
                    print("    Warning: no JWT found in page storage/cookies.")
                    print(f"    Storage keys seen: {response.get('tokenKeys')}")

                if status != 200:
                    print(f"    HTTP {status}: {body_text[:300]}")
                    results[ip] = {"status": f"Error HTTP {status}", "message": body_text[:200], "ticketId": "", "ticketUrl": ""}
                    time.sleep(1.0)
                    continue

                try:
                    data = json.loads(body_text)
                except json.JSONDecodeError:
                    print(f"    Bad JSON: {body_text[:300]}")
                    results[ip] = {"status": "Error bad JSON", "message": body_text[:200], "ticketId": "", "ticketUrl": ""}
                    time.sleep(1.0)
                    continue

                if idx == 1:
                    print("    Sample response:")
                    print(json.dumps(data, indent=2, ensure_ascii=False)[:600])

                code = data.get("code")
                message = data.get("message", "")
                data_obj = data.get("data")
                # Some actions (e.g. UpdateInstanceUnhealthyTag) return {"data": "success"}
                # with no ticket object — treat any non-dict payload as "no ticket".
                if not isinstance(data_obj, dict):
                    data_obj = {}
                ticket_id = data_obj.get("ticketId") or data_obj.get("ticket_id") or ""
                ticket_url = data_obj.get("ticketUrl") or data_obj.get("ticket_url") or ""

                status_str = "Submitted" if (code == 0 or str(message).lower() in ("success", "ok")) else f"Failed (code={code})"

                results[ip] = {
                    "status": status_str,
                    "message": str(message),
                    "ticketId": str(ticket_id),
                    "ticketUrl": str(ticket_url),
                }

                print(f"    → {status_str} | {message}")
                if ticket_url:
                    print(f"    → {ticket_url}")

                # Register with pipeline_state so the worker thread, the
                # overlap check, and the menu summary line all pick this up.
                # Wrapped defensively: a state-file hiccup should never take
                # down an otherwise-successful submit.
                if status_str == "Submitted" and ticket_id:
                    try:
                        pipeline_start_entry(
                            str(ip),
                            stage=action.lower(),
                            ticket_id=str(ticket_id),
                            ticket_url=str(ticket_url),
                            partition=str(data_obj.get("partition", "")),
                            source=f"menu:{action.lower()}",
                        )
                    except Exception as state_err:
                        print(f"    (pipeline state not updated: {state_err})")

            except Exception as e:
                print(f"    Exception: {e}")
                results[ip] = {"status": f"Error: {e}", "message": str(e), "ticketId": "", "ticketUrl": ""}

            time.sleep(1.0)

    except Exception as e:
        print(f"{action} error: {e}")
        raise

    submitted = sum(1 for r in results.values() if r.get("status") == "Submitted")
    print(f"\n  Done: {submitted}/{len(unique_ips)} submitted successfully.")
    print("(Browser left open for reuse. It will close when you exit the dashboard.)")
    return results


def run_reboots(ip_list: list, dry_run: bool = False, confirm: bool = True) -> dict:
    return _run_operation_per_ip(
        ip_list, dry_run,
        action="Reboot", page_url=REBOOT_PAGE, confirm_word="REBOOT",
        label="rebooted", verb="Rebooting", confirm=confirm,
    )


def run_reinstalls(ip_list: list, dry_run: bool = False, confirm: bool = True) -> dict:
    return _run_operation_per_ip(
        ip_list, dry_run,
        action="Reinstall", page_url=REINSTALL_PAGE, confirm_word="REINSTALL",
        label="reinstalled", verb="Reinstalling", confirm=confirm,
        extra_payload={"image": "default", "initScript": "default"},
    )


def run_recreates(ip_list: list, dry_run: bool = False, confirm: bool = True) -> dict:
    return _run_operation_per_ip(
        ip_list, dry_run,
        action="Recreate", page_url=RECREATE_PAGE, confirm_word="RECREATE",
        label="recreated", verb="Recreating", confirm=confirm,
        extra_payload={"image": "default", "initScript": "default"},
    )


def run_unhealthy_tags(ip_list: list, dry_run: bool = False, confirm: bool = True) -> dict:
    """UpdateInstanceUnhealthyTag (addOrDelete=add). Body shape copied from a real
    captured request. The API answers synchronously with {"code":0,"data":"success"}
    and no ticket, so nothing is registered in the pipeline for this step."""
    return _run_operation_per_ip(
        ip_list, dry_run,
        action="UpdateInstanceUnhealthyTag", page_url=UNHEALTHY_TAG_PAGE,
        confirm_word="TAG", label="tagged unhealthy", verb="Tagging", confirm=confirm,
        extra_payload={
            "action": "UpdateInstanceUnhealthyTag",
            "identifiedBy": "ip",
            "ocids": [],
            "instanceIds": [],
            "skipSrcDstCheck": True,
            "addOrDelete": "add",
            "targetFirmwareBundleId": "",
        },
    )


def _gpu_shape_mask(df: pd.DataFrame) -> pd.Series:
    wanted = {s.lower() for s in GPU_RECREATE_SHAPES}
    mask = pd.Series(False, index=df.index)
    for col in ("product", "model"):
        if col in df.columns:
            mask |= df[col].astype(str).str.strip().str.lower().isin(wanted)
    return mask


def do_gpu_unhealthy_recreate_workflow(dry_run: bool = False):
    """Menu G (I18N): export to_be_confirmed tickets -> keep BM.GPU.L40S-NC.4 /
    BM.GPU.A10.4 / BM.GPU.T1.2 -> UpdateInstanceUnhealthyTag -> Recreate (only the
    hosts whose tag call succeeded). Intake deliberately skips the product
    exclusion in apply_filters() (which drops anything containing "GPU")."""
    region = "i18n"
    path = export_tickets_from_web(region)
    df = load_tickets(path)
    df["region"] = REGION_CONFIG[region]["label"]

    work = df.loc[_gpu_shape_mask(df)].copy()
    if work.empty:
        print("\nNo tickets matched the GPU shapes.")
        for col in ("product", "model"):
            if col in df.columns:
                seen = sorted({str(v) for v in df[col].dropna() if "gpu" in str(v).lower()})
                if seen:
                    print(f"  {col} values containing 'gpu': {seen}")
        return

    # Same hygiene as the normal intake, minus the product exclusion.
    if "operator_name" in work.columns:
        op_pat = "|".join(re.escape(str(x)) for x in EXCLUDE_OPERATORS)
        work = work.loc[~work["operator_name"].astype(str).str.contains(op_pat, case=False, na=False)]
    for col in [c for c in ("request_psm_name", "allow_psm_name", "not_allow_psm_name") if c in work.columns]:
        psm_pat = "|".join(re.escape(str(x)) for x in EXCLUDE_PSM_KEYWORDS)
        work = work.loc[~work[col].astype(str).str.contains(psm_pat, case=False, na=False)]

    work = enrich(work)
    work = work[work["check_ip"].notna() & (work["check_ip"].astype(str).str.strip() != "")]
    work = work.drop_duplicates(subset="check_ip").reset_index(drop=True)
    if work.empty:
        print("\nNothing left after operator/PSM exclusions.")
        return

    print("\n========================================")
    print(f"  GPU unhealthy-tag -> recreate candidates: {len(work)}")
    print("========================================")
    for i, row in work.iterrows():
        detail = str(row.get("detail", ""))[:60]
        print(f"  {i + 1:3d}. {row.get('id', '')}  {row.get('product', '')}  {row['check_ip']}  | {detail}")

    # Pre-list in the usual ticketq layout so the matches can be eyeballed against
    # the filters BEFORE anything is tagged. Deliberately NOT named ticketq_result_*
    # so options 2/7 never auto-pick it up as "the last ticketq result".
    work["status"] = "GPU candidate - tag unhealthy then recreate"
    work["recommended_next_step"] = "Review, then confirm in the menu to tag unhealthy + recreate"
    work["port22_result"] = "Not checked"
    pre_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    pre_out = path.parent / f"gpu_candidates_{pre_ts}.xlsx"
    build_ticketq_workbook(work, path.name, len(df)).save(pre_out)
    print(f"\nPre-list saved: {pre_out}")
    open_file(pre_out)
    if input("Review the Excel. Proceed to tag these as unhealthy? [y/N]: ").strip().lower() != "y":
        print("Cancelled. Nothing was tagged.")
        return

    limit_raw = input("\nHow many to process this run? (Enter = all, e.g. 1 for a test): ").strip()
    if limit_raw.isdigit() and int(limit_raw) > 0:
        work = work.head(int(limit_raw)).copy()
        print(f"  Limited to the first {len(work)}.")

    ip_list = pipeline_confirm_overlap(work["check_ip"].astype(str).tolist())
    if not ip_list:
        print("Nothing left after overlap check.")
        return
    work = work[work["check_ip"].astype(str).isin(ip_list)].copy()

    tag_results = run_unhealthy_tags(ip_list, dry_run=dry_run)
    if not tag_results and not dry_run:
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag_out = path.parent / f"unhealthy_tag_result_{ts}.xlsx"
    build_operation_workbook(work, tag_results, path.name, op_name="unhealthy_tag").save(tag_out)
    print(f"\nSaved: {tag_out}")
    if dry_run:
        print("[DRY-RUN] Skipping recreate step.")
        return

    tagged = [ip for ip, r in tag_results.items() if r.get("status") == "Submitted"]
    failed = [ip for ip in tag_results if ip not in tagged]
    print(f"\nTag step: {len(tagged)} succeeded, {len(failed)} not tagged.")
    for ip in failed:
        print(f"  NOT tagged (will NOT be recreated): {ip} -> {tag_results[ip].get('status')} {tag_results[ip].get('message')}")
    if not tagged:
        return

    print("\nProceeding to RECREATE only the hosts that were tagged successfully.")
    rec_results = run_recreates(tagged, dry_run=False)
    if not rec_results:
        return
    rec_work = work[work["check_ip"].astype(str).isin(tagged)].copy()
    rec_out = path.parent / f"recreate_result_{ts}.xlsx"
    build_operation_workbook(rec_work, rec_results, path.name, op_name="recreate").save(rec_out)
    print(f"\nSaved: {rec_out}")
    open_file(rec_out)
    print("Done.")


def build_operation_workbook(work: pd.DataFrame, results: dict, source_name: str, op_name: str = "reboot") -> Workbook:
    """Builds the results workbook for any per-IP operation (reboot, reinstall, ...).
    op_name is used both as the column prefix (e.g. 'reboot_status') and in the
    sheet title/summary heading (e.g. 'Reboot Results')."""
    work = work.copy()
    status_col = f"{op_name}_status"
    message_col = f"{op_name}_message"
    ticket_id_col = f"{op_name}_ticketId"
    ticket_url_col = f"{op_name}_ticketUrl"

    work[status_col] = work["check_ip"].map(lambda ip: results.get(str(ip), {}).get("status", ""))
    work[message_col] = work["check_ip"].map(lambda ip: results.get(str(ip), {}).get("message", ""))
    work[ticket_id_col] = work["check_ip"].map(lambda ip: results.get(str(ip), {}).get("ticketId", ""))
    work[ticket_url_col] = work["check_ip"].map(lambda ip: results.get(str(ip), {}).get("ticketUrl", ""))

    preferred = [
        "id", "type", "detail", "check_ip", "port22_result",
        status_col, message_col, ticket_id_col, ticket_url_col,
        "link", "product", "operator_name", "created", "status",
    ]
    cols = [c for c in preferred if c in work.columns]
    extra = [c for c in work.columns if c not in cols]
    work = work[cols + extra]

    wb = Workbook()
    header_fill = PatternFill("solid", fgColor="1F4E79")
    header_font = Font(bold=True, color="FFFFFF")
    thin = Border(left=Side(style="thin"), right=Side(style="thin"), top=Side(style="thin"), bottom=Side(style="thin"))
    ok_fill = PatternFill("solid", fgColor="C6EFCE")
    fail_fill = PatternFill("solid", fgColor="FFC7CE")

    ws = wb.active
    ws.title = f"{op_name.capitalize()} Results"

    for col_idx, col_name in enumerate(work.columns, 1):
        cell = ws.cell(row=1, column=col_idx, value=col_name)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", wrap_text=True)
        cell.border = thin

    for row_idx, row in enumerate(work.itertuples(index=False), 2):
        for col_idx, value in enumerate(row, 1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.border = thin
            cell.alignment = Alignment(wrap_text=True, vertical="center")
        if status_col in work.columns:
            res_col = work.columns.get_loc(status_col) + 1
            val = str(row[work.columns.get_loc(status_col)]).lower()
            cell = ws.cell(row=row_idx, column=res_col)
            if "submitted" in val or "success" in val:
                cell.fill = ok_fill
            elif "fail" in val or "error" in val:
                cell.fill = fail_fill

    widths = {
        "id": 12, "type": 10, "detail": 30, "check_ip": 22, "port22_result": 14,
        status_col: 14, message_col: 18, ticket_id_col: 36,
        ticket_url_col: 55, "link": 40, "product": 24, "operator_name": 16,
        "created": 18, "status": 18,
    }
    for col_idx, col_name in enumerate(work.columns, 1):
        ws.column_dimensions[get_column_letter(col_idx)].width = widths.get(col_name, 14)

    ws.auto_filter.ref = ws.dimensions
    ws.freeze_panes = "A2"

    ws2 = wb.create_sheet("Summary")
    ws2["A1"] = f"{op_name.capitalize()} Results"
    ws2["A1"].font = Font(bold=True, size=14)
    ws2["A2"] = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    ws2["A3"] = f"Source: {source_name}"
    ws2["A4"] = f"IPs: {len(work)}"
    ws2.column_dimensions["A"].width = 50

    return wb


def build_reboot_workbook(work: pd.DataFrame, results: dict, source_name: str) -> Workbook:
    return build_operation_workbook(work, results, source_name, op_name="reboot")





def do_reboot_from_excel(dry_run: bool = False):
    path = find_latest_result()
    if path is None:
        print("No ticketq_result_*.xlsx found. Run option 1 first.")
        return

    print("\n========================================")
    print(f"  Excel file : {path.name}")
    print("========================================\n")

    work = load_unreachable(path)
    print(f"Unreachable rows: {len(work)}")
    if work.empty:
        print("Nothing to reboot.")
        return

    ip_list = work["check_ip"].astype(str).tolist()
    ip_list = pipeline_confirm_overlap(ip_list)
    if not ip_list:
        print("Nothing left to reboot after overlap check.")
        return
    results = run_reboots(ip_list, dry_run=dry_run)
    if not results and not dry_run:
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = path.parent / f"reboot_result_{ts}.xlsx"
    wb = build_reboot_workbook(work, results, path.name)
    wb.save(out)
    print(f"\nSaved: {out}")
    open_file(out)
    print("Done.")


def do_reboot_manual(dry_run: bool = False):
    print()
    print("Enter IP addresses to reboot.")
    print("  - Separate multiple IPs with commas")
    print("  - Or paste several lines, then press ENTER on an empty line")
    print()

    lines = []
    while True:
        try:
            line = input("IP(s): " if not lines else "").strip()
        except EOFError:
            break
        if not line:
            break
        lines.append(line)

    raw = " ".join(lines).replace("\n", ",").replace(" ", ",")
    ips = [ip.strip() for ip in raw.split(",") if ip.strip()]

    if not ips:
        print("No IPs entered.")
        return

    print(f"\nYou entered {len(ips)} IP(s):")
    for i, ip in enumerate(ips, 1):
        print(f"  {i}. {ip}")
    print()

    confirm = input("Proceed? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Cancelled.")
        return

    ips = pipeline_confirm_overlap(ips)
    if not ips:
        print("Nothing left to reboot after overlap check.")
        return
    results = run_reboots(ips, dry_run=dry_run)
    if not results and not dry_run:
        return

    work = pd.DataFrame({"check_ip": ips})
    work["port22_result"] = "Manual"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path.cwd() / f"reboot_result_{ts}.xlsx"
    wb = build_reboot_workbook(work, results, "manual_input")
    wb.save(out)
    print(f"\nSaved: {out}")
    open_file(out)
    print("Done.")


def do_recreate_from_tickets(dry_run: bool = False):
    """Ticket-sourced counterpart to do_recreate_manual: reads Recreate
    candidates (tagged by do_ticketq via RECREATE_DETAIL_KEYWORDS) straight
    out of the last ticketq_result_*.xlsx instead of manual IP paste."""
    path = find_latest_result()
    if path is None:
        print("No ticketq_result_*.xlsx found. Run option 1 or 6 first.")
        return

    print("\n========================================")
    print(f"  Excel file : {path.name}")
    print("========================================\n")

    work = load_recreate_candidates(path)
    print(f"Recreate candidates: {len(work)}")
    if work.empty:
        print("Nothing to recreate.")
        return

    ip_list = work["check_ip"].astype(str).tolist()
    ip_list = pipeline_confirm_overlap(ip_list)
    if not ip_list:
        print("Nothing left to recreate after overlap check.")
        return
    results = run_recreates(ip_list, dry_run=dry_run)
    if not results and not dry_run:
        return

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = path.parent / f"recreate_result_{ts}.xlsx"
    wb = build_operation_workbook(work, results, path.name, op_name="recreate")
    wb.save(out)
    print(f"\nSaved: {out}")
    open_file(out)
    print("Done.")


def do_reinstall_manual(dry_run: bool = False):
    print()
    print("Enter IP addresses to REINSTALL.")
    print("  *** This wipes the OS on each machine (image=default, initScript=default). ***")
    print("  - Separate multiple IPs with commas")
    print("  - Or paste several lines, then press ENTER on an empty line")
    print()

    lines = []
    while True:
        try:
            line = input("IP(s): " if not lines else "").strip()
        except EOFError:
            break
        if not line:
            break
        lines.append(line)

    raw = " ".join(lines).replace("\n", ",").replace(" ", ",")
    ips = [ip.strip() for ip in raw.split(",") if ip.strip()]

    if not ips:
        print("No IPs entered.")
        return

    print(f"\nYou entered {len(ips)} IP(s) to REINSTALL:")
    for i, ip in enumerate(ips, 1):
        print(f"  {i}. {ip}")
    print()

    confirm = input("Proceed? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Cancelled.")
        return

    ips = pipeline_confirm_overlap(ips)
    if not ips:
        print("Nothing left to reinstall after overlap check.")
        return
    results = run_reinstalls(ips, dry_run=dry_run)
    if not results and not dry_run:
        return

    work = pd.DataFrame({"check_ip": ips})
    work["port22_result"] = "Manual"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path.cwd() / f"reinstall_result_{ts}.xlsx"
    wb = build_operation_workbook(work, results, "manual_input", op_name="reinstall")
    wb.save(out)
    print(f"\nSaved: {out}")
    open_file(out)
    print("Done.")


def do_recreate_manual(dry_run: bool = False):
    print()
    print("Enter IP addresses to RECREATE.")
    print("  *** This recreates each machine from scratch (image=default, initScript=default). ***")
    print("  - Separate multiple IPs with commas")
    print("  - Or paste several lines, then press ENTER on an empty line")
    print()

    lines = []
    while True:
        try:
            line = input("IP(s): " if not lines else "").strip()
        except EOFError:
            break
        if not line:
            break
        lines.append(line)

    raw = " ".join(lines).replace("\n", ",").replace(" ", ",")
    ips = [ip.strip() for ip in raw.split(",") if ip.strip()]

    if not ips:
        print("No IPs entered.")
        return

    print(f"\nYou entered {len(ips)} IP(s) to RECREATE:")
    for i, ip in enumerate(ips, 1):
        print(f"  {i}. {ip}")
    print()

    confirm = input("Proceed? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Cancelled.")
        return

    ips = pipeline_confirm_overlap(ips)
    if not ips:
        print("Nothing left to recreate after overlap check.")
        return
    results = run_recreates(ips, dry_run=dry_run)
    if not results and not dry_run:
        return

    work = pd.DataFrame({"check_ip": ips})
    work["port22_result"] = "Manual"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path.cwd() / f"recreate_result_{ts}.xlsx"
    wb = build_operation_workbook(work, results, "manual_input", op_name="recreate")
    wb.save(out)
    print(f"\nSaved: {out}")
    open_file(out)
    print("Done.")


# -------------------- menu --------------------

def export_tickets_from_web(region: str = "i18n", manufacturer: str = "oci",
                             progress: str = "to_be_confirmed", ids: list = None,
                             search: str = "") -> Path:
    """Calls the same POST EXPORT_API the website's own 'Excel' export
    button hits, and saves the returned .xlsx to disk. See EXPORT_API
    comment above for how this was confirmed (raw PK zip bytes, single
    synchronous request — no polling needed).
    Raises if the response doesn't look like a real xlsx, rather than silently
    saving garbage. Each region is saved with a distinct filename prefix.
    """
    region = normalize_region(region)
    if region == "both":
        raise ValueError("export_tickets_from_web() accepts one region at a time")
    config = REGION_CONFIG[region]
    page = get_playwright_page(config["export_page"], prompt_label=f"{config['label']} export page")
    captured_clean = _page_jwt_headers(page)
    jwt_value = captured_clean.get("X-Jwt-Token", "")
    if not jwt_value:
        raise RuntimeError(f"No X-Jwt-Token captured yet for {config['label']} — "
                            "reload the export page while logged in, then retry.")

    body = {
        "ips": "",
        "search": search,
        "ids": ids or [],
        "params": {"manufacturer": manufacturer, "progress": progress},
        "export": EXPORT_COLUMNS,
        "out_of_warranty": False,
    }

    print(f"Requesting {config['label']} export (manufacturer={manufacturer}, progress={progress})...")
    response = page.evaluate(
        """async ({url, jwt, body}) => {
            const res = await fetch(url, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'accept': 'application/json',
                    'content-type': 'application/json; charset=UTF-8',
                    'x-jwt-token': jwt
                },
                body: JSON.stringify(body)
            });
            const buf = await res.arrayBuffer();
            const bytes = new Uint8Array(buf);
            let binary = '';
            for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
            return { status: res.status, contentType: res.headers.get('content-type'), b64: btoa(binary) };
        }""",
        {"url": config["export_api"], "jwt": jwt_value, "body": body},
    )

    status = response.get("status")
    if status != 200:
        raise RuntimeError(f"Export request failed: HTTP {status} "
                            f"(content-type: {response.get('contentType')})")

    raw = base64.b64decode(response["b64"])
    if raw[:2] != b"PK":
        raise RuntimeError(
            "Export response wasn't a valid .xlsx (missing PK zip signature) — "
            "site/auth may have changed. First 40 bytes: " + repr(raw[:40])
        )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path.cwd() / f"{config['output_prefix']}_{ts}.xlsx"
    out.write_bytes(raw)
    print(f"Exported {len(raw)} bytes -> {out}")
    return out


def fetch_fault_ticket_detail(page, ticket_id) -> dict:
    """GET /app/fault/ticket/{ticket_id}/detail on fault-i18n.tiktok-row.net.
    Confirmed (via a real captured response) to return clean JSON, not HTML —
    mount point lives at backup_list[].mount. Reuses the same in-page fetch()
    + JWT-capture pattern as the rest of this script; the JWT header this
    site expects ('X-Jwt-Token') is already in get_playwright_page()'s
    watched header list, so no new auth mechanism is needed — just visiting
    a fault-i18n page in the shared persistent browser is enough for the
    existing interceptor to pick it up.
    """
    url = FAULT_TICKET_DETAIL_URL_TEMPLATE.format(ticket_id=ticket_id)
    captured_clean = _sanitize_jwt_map(_captured_jwt_headers)
    jwt_value = captured_clean.get("X-Jwt-Token", "")

    response = page.evaluate(
        """async ({url, jwt}) => {
            const res = await fetch(url, {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'accept': 'application/json',
                    'X-Jwt-Token': jwt
                }
            });
            const text = await res.text();
            return { status: res.status, body: text };
        }""",
        {"url": url, "jwt": jwt_value},
    )
    status = response.get("status")
    body_text = response.get("body", "")
    if status != 200:
        return {"_error": f"HTTP {status}", "_body": body_text[:300]}
    try:
        return json.loads(body_text)
    except json.JSONDecodeError:
        return {"_error": "bad JSON (got HTML? check content-type)", "_body": body_text[:300]}


NVME_DEVICE_RE = re.compile(r"^(nvme\d+)n\d+(?:p\d+)?$", re.I)


def parse_nvme_fault_ticket(detail: dict) -> list:
    """Pure function (no network). From a fault-ticket detail JSON
    (GET /app/fault/ticket/{id}/detail) return one dict per NVMe fault entry in
    `backup_list`. Layout confirmed from a real ticket (2354794):
      device  <- backup_list[].part      e.g. "nvme10n1"
      PCIe    <- backup_list[].location  e.g. "0000:81:00.0"
      disk SN <- backup_list[].sn        (NOT the top-level `sn`, which is the instance OCID)
    The controller is parsed with a regex: "nvme10n1" -> "nvme10". Never strip the
    last two characters — that would turn nvme10n1 into nvme1 (the wrong drive)."""
    if not isinstance(detail, dict) or "_error" in detail:
        return []
    rows = []
    for e in detail.get("backup_list") or []:
        if str(e.get("ctype", "")).upper() != "NVME":
            continue
        part = str(e.get("part", "")).strip()
        m = NVME_DEVICE_RE.match(part)
        rows.append({
            "ticket_id": detail.get("id"),
            "host_sn": detail.get("host_sn"),
            "ip": detail.get("ipv4") or detail.get("ip"),
            "hostname": detail.get("hostname"),
            "idc": detail.get("idc"),
            "device": part,
            "controller": m.group(1) if m else "",
            "pcie_location": e.get("location"),
            "disk_sn": e.get("sn"),
            "disk_model": e.get("model") or e.get("pn"),
            "mount": e.get("mount"),
            "fault_detail": e.get("detail"),
            "fault_description": e.get("description"),
            "fault_code": e.get("fault_code"),
            "soft_or_hard": e.get("soft_or_hard"),
        })
    return rows



def ticket_has_readonly_root_mount(detail_json: dict) -> bool:
    """True only if the ticket's backup_list contains a FileSystem /
    'FS Readonly From Mount' entry whose mount is EXACTLY '/' — not
    '/data00', '/data01', or any other mount point. Exact-match by
    design, not a prefix/substring check, per explicit requirement."""
    if not isinstance(detail_json, dict) or "_error" in detail_json:
        return False
    for entry in detail_json.get("backup_list") or []:
        entry_type = str(entry.get("type", ""))
        entry_detail = str(entry.get("detail", ""))
        entry_mount = str(entry.get("mount", "")).strip()
        if (entry_type.lower() == "filesystem"
                and any(kw.lower() in entry_detail.lower() for kw in FILESYSTEM_DETAIL_KEYWORDS)
                and entry_mount == "/"):
            return True
    return False


def do_filesystem_debug_test():
    """TEMPORARY / DEBUG ONLY — validates the fault-i18n mount-point lookup
    against one real ticket before it goes anywhere near the batch filter.
    Read-only: only ever GETs, never submits/mutates anything."""
    print("\n--- Filesystem mount-point debug test ---")
    ticket_id = input("Paste a ticket ID (e.g. 2509502): ").strip()
    if not ticket_id:
        print("No ticket ID entered, aborting.")
        return

    page_url = FAULT_TICKET_PAGE_TEMPLATE.format(ticket_id=ticket_id)
    try:
        page = get_playwright_page(page_url, prompt_label="fault-i18n page")
    except Exception as e:
        print(f"Could not open fault-i18n page: {e}")
        return

    print("\nFetching ticket detail...")
    detail = fetch_fault_ticket_detail(page, ticket_id)
    print(json.dumps(detail, indent=2, ensure_ascii=False)[:3000])

    if "_error" in detail:
        print(f"\nStopped: {detail['_error']}")
        return

    matched = ticket_has_readonly_root_mount(detail)
    print(f"\nticket_has_readonly_root_mount() -> {matched}")
    for entry in detail.get("backup_list") or []:
        print(f"  backup_list entry: type={entry.get('type')!r} "
              f"detail={entry.get('detail')!r} mount={entry.get('mount')!r}")
    print("\n--- End debug test. Compare the raw mount values above against "
          "the True/False result — does it look right? ---")


def _do_alto_debug_test_one(ticket_url: str):
    """TEMPORARY / DEBUG ONLY — not part of the pipeline itself.
    Runs the Alto polling chain against one real ticket_url you paste in,
    printing raw JSON at every step alongside the interpreted result, so we
    can confirm the field names _alto_find_active_node_key() and
    alto_poll_ticket_status() assume actually match a real response before
    any of this gets wired into the unattended worker thread. Safe to run
    any number of times — this only ever GETs, never submits/mutates
    anything."""
    print("\n--- Alto polling debug test ---")
    alto_domain = pipeline_alto_domain_from_ticket_url(ticket_url)
    if not alto_domain:
        print("Could not parse a domain out of that URL.")
        return

    # ticket_id is the last path segment, e.g. ".../ticket-audit/ticket_7f3f..."
    # Real Alto ticket-audit links commonly carry a "#detail" fragment
    # (both real URLs tested so far had one) — urlparse splits that off
    # (and any "?query") before we take the last path segment, since a
    # naive rstrip/rsplit on "/" alone leaves "#detail" glued onto the
    # ticket_id, which then gets embedded in every request path below and
    # gets silently truncated by fetch()'s own URL-fragment handling —
    # collapsing /action, /variables, and /histories into the same bare
    # request with no suffix and no query string at all.
    ticket_id = urlparse(ticket_url).path.rstrip("/").rsplit("/", 1)[-1]
    print(f"  alto_domain: {alto_domain}")
    print(f"  ticket_id:   {ticket_id}")

    try:
        page = get_alto_page(alto_domain, sample_ticket_url=ticket_url, prompt_label="Alto debug page")
    except Exception as e:
        print(f"Could not open Alto page: {e}")
        return

    print("\n[1/4] Polling /action ...")
    action_data = alto_poll_action(page, ticket_id)
    print(json.dumps(action_data, indent=2)[:3000])

    if "_error" in action_data:
        print(f"\nStopped: {action_data['_error']}")
        return

    node_key = _alto_find_active_node_key(action_data)
    print(f"\n[2/4] Heuristic picked active node_key: {node_key!r}")
    print("      (Check this against the raw ticket_nodes above — is this")
    print("       really the currently-running call_activity, or a settled")
    print("       / untouched sibling branch?)")

    if node_key:
        print("\n[3/4] Polling /sub_tickets for that node ...")
        sub_data = alto_get_sub_tickets(page, ticket_id, node_key)
        print(json.dumps(sub_data, indent=2)[:3000])

    print("\n[4/4] Running full alto_poll_ticket_status() interpretation ...")
    result = alto_poll_ticket_status(page, ticket_id)
    print(json.dumps(result, indent=2))

    if result.get("state") == "failed" and result.get("child_ticket_id"):
        print("\n(state=failed, so /variables was already queried internally")
        print(" for the *_detail field above.)")

    # Always dump /variables and /histories for the pasted ticket_id too —
    # unconditionally, not gated on the interpreted state above. A ticket
    # can be actively retrying (state='running') while an individual
    # attempt has already failed and left a trace in one of these; this
    # is the only way to see that without waiting for the ticket to go
    # terminal.
    print("\n[extra] /variables for this exact ticket_id (unconditional) ...")
    extra_vars = alto_get_variables(page, ticket_id)
    print(json.dumps(extra_vars, indent=2)[:3000])
    found_detail = _extract_alto_detail_field(extra_vars)
    if found_detail:
        print(f"  -> found *_detail field: {found_detail!r}")
    else:
        print("  -> no *_detail field found (checked both the real "
              "ticket_variables.variables list shape and a flat-dict fallback)")

    print("\n[extra] /histories for this exact ticket_id (unconditional) ...")
    extra_hist = alto_get_histories(page, ticket_id)
    print(json.dumps(extra_hist, indent=2)[:3000])
    failure_events = _find_alto_failure_events(extra_hist)
    if failure_events:
        print(f"\n  -> {len(failure_events)} entr{'y' if len(failure_events) == 1 else 'ies'} "
              f"in this history look like an actual failure (not just a state change):")
        for ev in failure_events:
            print(json.dumps(ev, indent=2, ensure_ascii=False))
    else:
        print("  -> no failure-looking entries found in this histories page "
              "(only ready/running/finished state-change events, or none at all)")

    print("\n[extra] Unrecoverable-failure signature scan (variables + histories) ...")
    unrecoverable = _scan_for_unrecoverable_failure(extra_vars, extra_hist)
    if unrecoverable:
        print(f"  -> MATCH (would be treated as 'failed' even though state may still say "
              f"'running'): ...{unrecoverable}...")
    else:
        print(f"  -> no match against known patterns ({ALTO_UNRECOVERABLE_FAILURE_PATTERNS})")

    print("\n--- End debug test. Compare the interpreted result above against")
    print("    the raw JSON — does state/detail/child_ticket_id look right? ---")


def do_alto_debug_test():
    """Run the read-only Alto diagnostic against one or more ticket URLs."""
    print("\n--- Alto polling debug test ---")
    print("Paste one ticketUrl per line; press ENTER on an empty line when done.")
    urls = []
    while True:
        value = input("ticketUrl: ").strip()
        if not value:
            break
        urls.append(value)

    if not urls:
        print("No URLs entered, aborting.")
        return

    print(f"Running read-only Alto diagnostics for {len(urls)} ticket(s).")
    for index, ticket_url in enumerate(urls, 1):
        print(f"\n===== Ticket {index}/{len(urls)} =====")
        _do_alto_debug_test_one(ticket_url)


def do_pipeline_clear():
    """Lists everything currently tracked — both the main pipeline
    (pipeline_state.json) and any in-flight OS EIPv4/EIPv6 dual-IP
    reinstalls (DUAL_IP_STATE_FILE) — and lets the person clear one,
    several, or all entries. Clearing only removes it from live tracking —
    it does NOT touch Alto or cancel the underlying ticket; the ticket
    keeps running/exists server-side regardless. This is for dropping
    stale/incorrect/no-longer-relevant tracking entries, not for
    cancelling operations."""
    entries = pipeline_all_entries()
    dual_entries = dict(_dual_ip_pending)

    if not entries and not dual_entries:
        print("\nNothing currently tracked (pipeline or dual-IP).")
        return

    print("\n--- Tracked entries ---")
    # (source, ip) so a numbered pick can be dispatched to the right clearer.
    combined = [("pipeline", ip) for ip in sorted(entries.keys())] + \
               [("dual_ip", ip) for ip in sorted(dual_entries.keys())]
    for i, (source, ip) in enumerate(combined, 1):
        if source == "pipeline":
            e = entries[ip]
            print(f"  {i}. {ip:<16} stage={e.get('stage','?'):<10} "
                  f"state={e.get('state','?'):<26} updated={e.get('updated_at','?')}")
        else:
            e = dual_entries[ip]
            print(f"  {i}. {ip:<16} [dual-ip reinstall] state={e.get('state','?'):<26} "
                  f"detail={e.get('detail','') or '-'}")
    print()
    print("Enter number(s) to clear (comma-separated), 'all' to clear everything,")
    choice = input("or ENTER to cancel: ").strip()

    if not choice:
        print("Cancelled.")
        return

    if choice.lower() == "all":
        confirm = input(f"Clear all {len(combined)} tracked entr{'y' if len(combined) == 1 else 'ies'}? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Cancelled.")
            return
        for ip in entries.keys():
            pipeline_clear_entry(ip)
        if dual_entries:
            _dual_ip_clear()
        print(f"Cleared {len(combined)} entr{'y' if len(combined) == 1 else 'ies'}.")
        return

    picked = []
    for part in choice.split(","):
        part = part.strip()
        if not part.isdigit():
            continue
        idx = int(part) - 1
        if 0 <= idx < len(combined):
            picked.append(combined[idx])

    if not picked:
        print("No valid selection.")
        return

    print("\nWill clear:")
    for source, ip in picked:
        print(f"  - {ip}" + (" [dual-ip reinstall]" if source == "dual_ip" else ""))
    confirm = input(f"Confirm clearing {len(picked)} entr{'y' if len(picked) == 1 else 'ies'}? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Cancelled.")
        return

    dual_ip_touched = False
    for source, ip in picked:
        if source == "pipeline":
            pipeline_clear_entry(ip)
        else:
            _dual_ip_pending.pop(ip, None)
            dual_ip_touched = True
    if dual_ip_touched:
        if _dual_ip_pending:
            _dual_ip_save_state()
        else:
            # Nothing left pending — drop the context too, same as a
            # completed run would.
            _dual_ip_clear()
    print(f"Cleared {len(picked)} entr{'y' if len(picked) == 1 else 'ies'}.")


def do_dry_run_menu():
    """Consolidated entry point for every dry-run preview — was previously
    two separate top-level menu options (reboot preview / recreate-ticket-
    flagged preview); grouped here so dry-run stays one place to look."""
    print("\n--- Dry-run ---")
    print("  1) Reboot preview (from last ticketq result)")
    print("  2) Recreate preview, ticket-flagged (from last ticketq result)")
    print("  0) Back")
    sub = input("Select dry-run option: ").strip()
    if sub == "1":
        do_reboot_from_excel(dry_run=True)
    elif sub == "2":
        do_recreate_from_tickets(dry_run=True)
    elif sub == "0":
        return
    else:
        print("Invalid option.")


def _save_and_open_operation_result(ips: list, results: dict, op_name: str, source_name: str = "pipeline_escalation"):
    """Same build-save-open pattern the manual do_* functions already use
    (see do_reinstall_manual/do_recreate_manual), factored out so an
    auto-escalated submit (triggered from a poll pass, not a menu pick)
    still produces the same Excel record with the ticket link — you
    shouldn't have to dig through pipeline_state.json to find it."""
    if not results:
        return
    work = pd.DataFrame({"check_ip": ips})
    work["port22_result"] = "Escalated"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path.cwd() / f"{op_name}_result_{ts}.xlsx"
    wb = build_operation_workbook(work, results, source_name, op_name=op_name)
    wb.save(out)
    print(f"    Saved: {out}")
    open_file(out)


def _pipeline_escalate(ip: str, current_stage: str, detail: str):
    """Applies the agreed escalation policy for an IP that didn't pass at
    current_stage (either Alto reported it failed, or Alto reported
    'finished' but the post-check port-22 recheck still came back
    unreachable — both are treated identically, since either way the
    stage didn't actually succeed).

    reboot -> auto-escalates to reinstall (submits it directly)
    reinstall -> stops at the recreate-approval gate (never auto-submits
                 the destructive step)
    recreate -> terminal; marked failed, needs a human to look at it
    """
    next_stage = pipeline_next_stage(current_stage)

    if not next_stage:
        pipeline_update_entry(ip, state="failed", detail=detail)
        print(f"    {ip}: {current_stage} did not succeed ({detail}) — no further "
              f"stage to escalate to. Marked failed, needs a manual look.")
        return

    if next_stage == "recreate":
        pipeline_update_entry(ip, state="awaiting_recreate_approval", detail=detail)
        print(f"    {ip}: {current_stage} did not succeed ({detail}) — ready to "
              f"escalate to recreate. Waiting on your approval (menu option 5/8).")
        return

    print(f"    {ip}: {current_stage} did not succeed ({detail}) — auto-escalating to {next_stage}.")
    if next_stage == "reinstall":
        results = run_reinstalls([ip])
        _save_and_open_operation_result([ip], results, op_name="reinstall")
    # (next_stage can only be "reinstall" here, since reboot is always the
    # first stage and recreate is handled by the branch above — but this
    # stays a simple if-chain rather than an assert so a future change to
    # PIPELINE_STAGE_ORDER doesn't silently crash a live poll run.)


def do_pipeline_poll_now():
    """Manual 'check on everything now' button. Walks every entry in
    pipeline_state.json currently in state == 'running', polls Alto for
    each, and applies the agreed outcome:
      finished + port-22 reachable  -> passed, cleared from tracking
      finished + port-22 unreachable -> treated as failed, escalates
      failed                         -> escalates (see _pipeline_escalate)
      running                        -> left as-is
      awaiting_review (Alto's own human-approval user_task) -> surfaced,
        left alone (that's Alto's own gate, not ours)

    Works from a fresh script run too — reads pipeline_state.json straight
    off disk (unaffected by the browser having been closed), and opens/
    re-authenticates the Alto browser session as needed via get_alto_page.

    Also checks in on any reinstall(s) submitted by the OS EIPv4/EIPv6
    workflow (menu N) that are still settling in the background — see
    do_dual_ip_poll_now (2026-09-21).
    """
    try:
        do_dual_ip_poll_now()
    except Exception as exc:
        # Defense in depth, added 2026-10-01 alongside the address_results
        # fix above: dual-IP polling runs BEFORE the normal pipeline below,
        # so an unhandled error here used to abort this whole function —
        # the normal reboot/reinstall/recreate entries never got polled at
        # all, which is what actually broke rather than anything region-
        # related. Report it and continue; dual-IP state is untouched and
        # "P" will retry it next time.
        print(f"\nDual-IP poll step hit an unexpected error (left as-is, will "
              f"retry next time \"P\" is run): {exc}")
        print("Continuing to the normal pipeline poll below...")

    entries = pipeline_all_entries()
    running = {ip: e for ip, e in entries.items() if e.get("state") == "running"}

    if not running:
        print("\nNothing currently in 'running' state to poll.")
        if entries:
            print(f"({len(entries)} other tracked entr{'y' if len(entries) == 1 else 'ies'} "
                  f"not polled — already settled/failed/awaiting approval.)")
        return

    print(f"\nPolling {len(running)} in-flight IP(s)...")
    # Alto polling itself is inherently per-ticket (each ip is a different
    # ticket_id, can't be batched) — but the port-22 RECHECK below is a
    # separate, genuinely batchable call (run_port22_checks already accepts
    # a list). It was previously fired one IP at a time, inside this same
    # loop, the moment each individual ip came back "finished" — meaning a
    # pass with several finished IPs made N separate port-22 round-trips
    # instead of 1. Collect them here and recheck once, after the polling
    # loop, in one batch (2026-09-18 fix).
    finished_ips = []
    finished_stage = {}
    finished_region = {}

    for ip, entry in running.items():
        stage = entry.get("stage", "?")
        alto_domain = entry.get("alto_domain", "")
        ticket_id = entry.get("ticket_id", "")
        ticket_url = entry.get("ticket_url", "")
        # Best-effort mapping from the submit API's raw "partition" value
        # (seen as "I18N" in testing) to run_port22_checks' region keys.
        # Falls back to i18n on anything ambiguous rather than guessing,
        # same reasoning as everywhere else region gets inferred in this file.
        partition = str(entry.get("partition", "")).strip().lower()
        region = "eu-ttp" if ("eu" in partition or "ttp" in partition) else "i18n"

        print(f"\n  [{ip}] stage={stage} ticket={ticket_id}")

        if not alto_domain or not ticket_id:
            print("    Skipping — missing alto_domain/ticket_id in tracked entry.")
            continue

        try:
            page = get_alto_page(alto_domain, sample_ticket_url=ticket_url,
                                  prompt_label=f"Alto page ({alto_domain})")
            result = alto_poll_ticket_status(page, ticket_id)
        except Exception as e:
            print(f"    Poll error: {e} (left as-is, try again later)")
            continue

        state = result.get("state")
        detail = result.get("detail", "")

        if state == "running":
            print("    Still running.")
            pipeline_update_entry(ip, detail=detail)

        elif state == "awaiting_review":
            print("    Awaiting Alto's own human-approval step (not our recreate gate).")
            pipeline_update_entry(ip, state="awaiting_review", detail=detail)

        elif state == "unknown":
            print(f"    Poll returned an unclear result ({detail}) — left as-is.")

        elif state == "finished":
            print("    Alto reports finished — queued for a batched port-22 recheck.")
            finished_ips.append(ip)
            finished_stage[ip] = stage
            finished_region[ip] = region

        elif state == "failed":
            _pipeline_escalate(ip, stage, detail or "Alto reported failed")

        else:
            print(f"    Unrecognized state '{state}' — left as-is.")

    if finished_ips:
        # Group by region so each region's port-test site gets its own real
        # batch call, rather than defaulting everything to i18n.
        by_region = {}
        for ip in finished_ips:
            by_region.setdefault(finished_region[ip], []).append(ip)

        print(f"\nRechecking port-22 for {len(finished_ips)} 'finished' IP(s) "
              f"in {len(by_region)} region-batch(es)...")
        port_results = {}
        for region_key, ips in by_region.items():
            port_results.update(run_port22_checks(ips, region=region_key))

        for ip in finished_ips:
            port_result = port_results.get(ip, "")
            if port_result == "Reachable":
                print(f"    [{ip}] Reachable — confirmed passed. Clearing from tracking.")
                pipeline_clear_entry(ip)
            else:
                print(f"    [{ip}] Still unreachable ({port_result}) despite Alto saying finished.")
                _pipeline_escalate(
                    ip, finished_stage[ip],
                    f"Alto reported finished but port-22 unreachable ({port_result})"
                )

    print("\nPoll pass complete.")


# ============================================================
# OS EIPv4 + EIPv6 UNREACHABLE WORKFLOW (menu option N)
# ============================================================

# ARIES_NIC_UNIT_ID / ARIES_NIC_SCRIPT_VERSION superseded 2026-09-23 by
# ARIES_REGION_CONFIG[region]["nic_unit_id"/"nic_script_version"] (further
# down this file) — kept here only as the i18n values for reference, no
# longer read anywhere.
ARIES_NIC_CHANGE_NAME = "Check Secondary NIC v1"
ARIES_NIC_CHECK_SCRIPT = r"""#!/usr/bin/env bash

ip a
echo ""
echo ""

if ! output=$(ip -o link show); then
    echo "ERROR: Unable to query network interfaces"
    exit 1
fi

failed=0

while IFS= read -r line; do
    if [[ "$line" == *"NO-CARRIER"* ]]; then
        iface=$(awk '{print $2}' <<< "$line")
        echo "ERROR: ${iface%:} has NO-CARRIER"
        failed=1
    fi
done <<< "$output"

if [[ "$failed" -eq 0 ]]; then
    echo "PASS: No interfaces with NO-CARRIER"
fi

exit "$failed"""


def _flatten_ip_values(value):
    if value is None:
        return []
    if isinstance(value, str):
        value = value.strip()
        return [value] if value else []
    if isinstance(value, list):
        out = []
        for item in value:
            out.extend(_flatten_ip_values(item))
        return out
    if isinstance(value, dict):
        out = []
        for key in ("ip", "address", "value", "privateIp", "privateIpAddress", "ipv4", "ipv6"):
            if key in value:
                out.extend(_flatten_ip_values(value.get(key)))
        return out
    return []


def _extract_secondary_ips(instance_record: dict) -> dict:
    """Extract OCI Compute secondaryIpv4 and secondaryIpv6 explicitly.

    The fields may be returned at the instance level or nested inside an
    interface/address object depending on the Compute view. We search the
    response recursively for the exact secondary-field names so a populated
    secondary IPv4 cannot be lost just because secondary IPv6 is also present.
    """
    ipv4, ipv6 = [], []

    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                key_norm = str(key).lower()
                if key_norm in ("secondaryipv4", "secondary_ipv4"):
                    ipv4.extend(_flatten_ip_values(child))
                elif key_norm == "secondaryipv6" or key_norm == "secondary_ipv6":
                    ipv6.extend(_flatten_ip_values(child))
                # Continue walking so nested Compute interface objects are covered.
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    if isinstance(instance_record, dict):
        walk(instance_record)

    return {
        "secondary_ipv4": list(dict.fromkeys(x for x in ipv4 if x)),
        "secondary_ipv6": list(dict.fromkeys(x for x in ipv6 if x)),
    }


def _find_instance_record_for_ip(inst_resp: dict, lookup_ip: str):
    records = inst_resp.get("data") or []
    if isinstance(records, dict):
        records = [records]
    lookup_ip = str(lookup_ip or "").strip()
    for record in records:
        if not isinstance(record, dict):
            continue
        for key in ("primaryIpv6", "primaryIPv6", "primaryIpv4", "primaryIPv4", "ipv6", "ipv4", "ip"):
            if lookup_ip in _flatten_ip_values(record.get(key)):
                return record
        if lookup_ip and lookup_ip in json.dumps(record, ensure_ascii=False):
            return record
    if len(records) == 1 and isinstance(records[0], dict):
        return records[0]
    return None


def _dual_ticket_primary_ipv6(row):
    for key in ("ipv6", "primaryIpv6", "primaryIPv6"):
        values = _flatten_ip_values(row.get(key))
        if values:
            return values[0]
    for key in ("ip", "check_ip", "ipv4"):
        values = _flatten_ip_values(row.get(key))
        if values:
            return values[0]
    return ""


def _secondary_reachability_by_ticket(rows: pd.DataFrame, ie_page):
    per_ticket = {}
    flat = []
    for idx, row in rows.iterrows():
        lookup_ip = _dual_ticket_primary_ipv6(row)
        item = {"lookup_ipv6": lookup_ip, "secondary_ipv4": "", "secondary_ipv6": "",
                "initial_secondary_results": "", "initial_reachable": False, "lookup_error": ""}
        if not lookup_ip:
            item["lookup_error"] = "No IPv6/IP available in ticket row for OCI lookup"
            per_ticket[idx] = item; continue
        resp = instance_batch_list(ie_page, [lookup_ip])
        if "_error" in resp:
            item["lookup_error"] = str(resp.get("_error")); per_ticket[idx] = item; continue
        record = _find_instance_record_for_ip(resp, lookup_ip)
        if not record:
            item["lookup_error"] = "OCI instance lookup returned no matching instance"
            per_ticket[idx] = item; continue
        sec = _extract_secondary_ips(record)
        item["secondary_ipv4"] = ", ".join(sec["secondary_ipv4"])
        item["secondary_ipv6"] = ", ".join(sec["secondary_ipv6"])
        addresses = sec["secondary_ipv4"] + sec["secondary_ipv6"]
        if not addresses:
            item["lookup_error"] = "OCI instance has no secondaryIpv4/secondaryIpv6 value"
            per_ticket[idx] = item; continue
        region = normalize_region(row.get("region", "i18n"))
        if region == "both": region = "i18n"
        for address in addresses:
            flat.append((idx, address, region))
        per_ticket[idx] = item

    if flat:
        by_region = {}
        for idx, address, region in flat:
            by_region.setdefault(region, []).append(address)
        for region, addresses in by_region.items():
            results = run_port22_checks(list(dict.fromkeys(addresses)), region=region)
            for idx, address, rgn in flat:
                if rgn == region and address in results:
                    per_ticket[idx].setdefault("address_results", {})[address] = results[address]
    for idx, item in per_ticket.items():
        # Bug fixed 2026-10-01: "address_results" (a raw {ip: status} dict,
        # internal to this function) used to stay in `item` after this loop.
        # Every caller does `dict(item)` straight into action_rows, which
        # eventually reaches build_dual_ip_workbook() -> an openpyxl cell —
        # and openpyxl refuses to write a dict value, raising exactly
        # "Cannot convert {...} to Excel". That crash was happening inside
        # do_dual_ip_poll_now(), which do_pipeline_poll_now() calls BEFORE
        # polling the normal reboot/reinstall/recreate pipeline — so it
        # looked like "dual-ip is breaking instead of letting the normal
        # poll continue", which is exactly what was happening: the
        # exception aborted do_pipeline_poll_now() before it ever reached
        # the main pipeline's entries. Popping the dict here (after using it
        # to build the two summary fields below) fixes it at the source, for
        # every caller, rather than patching each write site separately.
        addr_results = item.pop("address_results", {})
        item["initial_secondary_results"] = "; ".join(f"{ip}: {result}" for ip, result in addr_results.items())
        item["initial_reachable"] = any(v == "Reachable" for v in addr_results.values())
    return per_ticket


def _aries_nic_deployment_payload(name: str, ip: str, region: str = "i18n") -> dict:
    cfg = ARIES_REGION_CONFIG[normalize_region(region)]
    return {
        "name": name, "unitType": "script",
        "deployStrategy": {
            "mode": "simple", "user": "root", "bizArea": "cn",
            "hostAnalysisStrategy": "enable", "jobHandleStrategy": "pauseWhenFailed",
            "executeConfig": {"taskPersistPolicy": "none", "taskResource": {"type": "middle"}},
            "simple": {
                "targetPSMIDs": ["0"], "filter": {},
                "stageConfigs": [{"name": "100 %", "mode": "percent", "percent": 100,
                                  "preManualCheck": False, "autoManualCheck": True,
                                  "control": {"concurrence": 100}, "key": 0,
                                  "autoManualCheckers": [], "preManualCheckers": []}],
                "preManualCheck": False, "preManualCheckers": [],
                "autoManualCheck": True, "autoManualCheckers": [],
                "control": {"hostAggregationDimensions": [], "hostScatteringDimensions": [],
                             "timeout": 200, "postWait": 0, "maxFailNum": 100,
                             "concurrence": 10, "maxConcurrence": 10},
                "targetIPs": [ip],
            },
        },
        "approveStrategy": {"approvalProcesses": [{"type": "psm"}]},
        "changeLevel": "L3", "changeScene": "read_only", "changeDesp": {"emergency": False},
        "spec": {"taskType": "shell", "shell": {"entry": "/bin/bash", "script": ARIES_NIC_CHECK_SCRIPT},
                 "paramEncryption": False},
        "extra": {"changeApply": {"id": "", "platform": "SpaceX"}},
        "unitID": cfg["nic_unit_id"], "version": cfg["nic_script_version"],
    }


def aries_nic_precheck(page, name: str, ip: str, region: str = "i18n") -> dict:
    return _aries_fetch(page, aries_precheck_api(region), "POST", _aries_nic_deployment_payload(name, ip, region))


def aries_nic_deploy(page, name: str, ip: str, region: str = "i18n") -> dict:
    return _aries_fetch(page, aries_deploy_api(region), "POST", _aries_nic_deployment_payload(name, ip, region))


def classify_nic_taskdetail_entry(entry: dict) -> dict:
    status = str(entry.get("status", "") or "")
    err_code = entry.get("errCode")
    detail = entry.get("statusDetail") or {}
    reason = str(detail.get("reason", "") or "")
    stdout = str(entry.get("stdout", "") or "")
    stderr = str(entry.get("stderr", "") or "")
    combined = stdout + "\n" + stderr
    if "PASS: No interfaces with NO-CARRIER" in combined:
        return {"classification": "pass", "status": status, "err_code": err_code,
                "detail": "No interfaces with NO-CARRIER", "stdout": stdout, "stderr": stderr, "reason": reason}
    if re.search(r"ERROR:\s+\S+ has NO-CARRIER", combined, re.I):
        interfaces = re.findall(r"ERROR:\s+([^\s]+) has NO-CARRIER", combined, re.I)
        return {"classification": "no_carrier", "status": status, "err_code": err_code,
                "detail": "; ".join(interfaces) or "NO-CARRIER", "stdout": stdout, "stderr": stderr, "reason": reason}
    lost_reason = str(detail.get("lostReason", "") or "").strip()
    if err_code == 1001 or reason.startswith("Agent Lost Reason:") or lost_reason:
        return {"classification": "agent_lost", "status": status, "err_code": err_code,
                "detail": reason or lost_reason or "Agent Lost", "stdout": stdout, "stderr": stderr, "reason": reason}
    return {"classification": "unknown", "status": status, "err_code": err_code,
            "detail": reason or "Unexpected NIC-check result", "stdout": stdout, "stderr": stderr, "reason": reason}


def run_aries_nic_check(ip: str, aries_page, change_name: str, region: str = "i18n") -> dict:
    region = normalize_region(region)
    if not ARIES_REGION_CONFIG[region].get("nic_confirmed", True):
        print(f"  ⚠ NIC-check unitID/version for region {region!r} is UNCONFIRMED "
              f"(reusing i18n's as a best guess — no real {region.upper()} NIC "
              f"deployment has been captured yet). Treat this run's result with "
              f"caution until that's verified.")
    name = f"{change_name} - {ip}"
    rec = {"aries_nic_change_run": name, "aries_nic_link": "", "aries_nic_deployment_id": "",
           "aries_nic_job_id": "", "aries_nic_status": "", "aries_nic_classification": "",
           "aries_nic_detail": "", "aries_nic_stdout": "", "aries_nic_stderr": ""}
    pre = aries_nic_precheck(aries_page, name, ip, region)
    if "_error" in pre:
        rec["aries_nic_status"] = "precheck_error"; rec["aries_nic_detail"] = str(pre.get("_error")); return rec
    dep = aries_nic_deploy(aries_page, name, ip, region)
    if "_error" in dep:
        rec["aries_nic_status"] = "deploy_error"; rec["aries_nic_detail"] = str(dep.get("_error")); return rec
    deployment_id = dep.get("id") or dep.get("deploymentID") or (dep.get("data") or {}).get("id")
    if not deployment_id:
        rec["aries_nic_status"] = "deploy_incomplete"; rec["aries_nic_detail"] = "No deployment_id in Aries deploy response"; return rec
    rec["aries_nic_deployment_id"] = str(deployment_id)
    rec["aries_nic_link"] = _aries_deployment_link(str(deployment_id), "", region)
    print(f"    Deployment created: {deployment_id}  ({rec['aries_nic_link']})")
    deadline = time.time() + ARIES_POLL_TIMEOUT_SECONDS
    entry = None
    last_task = None
    while time.time() < deadline:
        task = aries_taskdetail(aries_page, str(deployment_id), region=region)  # unfiltered
        last_task = task
        if "_error" in task:
            rec["aries_nic_status"] = "poll_error"; rec["aries_nic_detail"] = str(task.get("_error")); return rec
        matches = [x for x in (task.get("data") or []) if _same_ip(x.get("ip", ""), ip)]
        if not matches and len(task.get("data") or []) == 1:
            matches = list(task["data"])
        if matches and _aries_status_terminal(matches[0].get("status", "")):
            entry = matches[0]; break
        time.sleep(ARIES_POLL_INTERVAL_SECONDS)
    if entry is None:
        rec["aries_nic_status"] = "no_task_data"
        diag = _aries_no_data_diagnostics(aries_page, str(deployment_id), region, last_task)
        rec["aries_nic_detail"] = f"No terminal task data after {ARIES_POLL_TIMEOUT_SECONDS}s | {diag}"
        print(f"    {rec['aries_nic_detail']}")
        return rec
    entry = _refetch_failed_entry(aries_page, deployment_id, entry, ip, region)
    job_id = entry.get("jobID") or entry.get("jobId") or ""
    rec["aries_nic_deployment_id"] = str(entry.get("deploymentID") or deployment_id)
    rec["aries_nic_job_id"] = str(job_id)
    rec["aries_nic_link"] = _aries_deployment_link(rec["aries_nic_deployment_id"], rec["aries_nic_job_id"], region)
    cr = classify_nic_taskdetail_entry(entry)
    rec["aries_nic_status"] = cr["status"]; rec["aries_nic_classification"] = cr["classification"]
    rec["aries_nic_detail"] = cr["detail"]; rec["aries_nic_stdout"] = cr["stdout"][:32000]; rec["aries_nic_stderr"] = cr["stderr"][:32000]
    return rec


def build_dual_ip_workbook(work: pd.DataFrame, results: dict, source_name: str) -> Workbook:
    out = work.copy()
    out["workflow"] = "OS EIPv4/EIPv6 unreachable"
    out["workflow_source"] = source_name
    result_df = pd.DataFrame([results.get(idx, {}) for idx in out.index], index=out.index)
    for col in result_df.columns: out[col] = result_df[col]
    wb = Workbook(); ws = wb.active; ws.title = "Dual-IP Results"
    for c, name in enumerate(out.columns, 1):
        cell = ws.cell(1, c, str(name)); cell.font = Font(bold=True); cell.alignment = Alignment(wrap_text=True)
    for r, row in enumerate(out.itertuples(index=False), 2):
        for c, value in enumerate(row, 1):
            # Belt-and-braces: pending state saved to disk BEFORE the 2026-10-01
            # address_results fix can still hold a raw {ip: status} dict, which
            # openpyxl refuses ("Cannot convert {...} to Excel"). Flatten any
            # non-scalar value to text instead of crashing the poll.
            if isinstance(value, dict):
                value = "; ".join(f"{k}: {v}" for k, v in value.items())
            elif isinstance(value, (list, tuple, set)):
                value = "; ".join(str(v) for v in value)
            ws.cell(r, c, value=value).alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "A2"; ws.auto_filter.ref = ws.dimensions
    for c, name in enumerate(out.columns, 1):
        if "link" in str(name).lower() or "url" in str(name).lower():
            for r in range(2, ws.max_row + 1):
                v = ws.cell(r, c).value
                if isinstance(v, str) and v.startswith(("http://", "https://")):
                    ws.cell(r, c).hyperlink = v; ws.cell(r, c).style = "Hyperlink"
    return wb


# Tracking for reinstalls submitted by the OS EIPv4/EIPv6 workflow that are
# still settling. PERSISTED to disk (2026-09-21 change, at user's request)
# so a crash/hang/restart doesn't lose track of a reinstall in flight — same
# atomic-write pattern as PIPELINE_STATE_FILE above. `df` (a DataFrame) and
# `ie_page` (a live Playwright page) are NOT JSON-serializable, so they are
# deliberately excluded from what's written to disk: `df` is reconstructed
# from the saved `path` (pd.read_excel is deterministic — nothing mutates df
# itself, only action_rows), and `ie_page` is lazily re-acquired the next
# time it's actually needed (a browser page can't survive a process restart
# anyway). Loaded once at import time below, so it's already in memory by
# the time you next press "P".
_dual_ip_pending = {}   # ip -> {"state", "detail", "ticket_url", "ticket_id", "domain"}
_dual_ip_context = {}   # everything do_dual_ip_poll_now() needs to finish the workflow


def _dual_ip_read_raw() -> dict:
    if not DUAL_IP_STATE_FILE.exists():
        return {}
    try:
        text = DUAL_IP_STATE_FILE.read_text(encoding="utf-8").strip()
        if not text:
            return {}
        return json.loads(text)
    except (json.JSONDecodeError, OSError):
        return {}


def _dual_ip_write_raw(data: dict):
    """Atomic write — same pattern as _pipeline_write_raw()."""
    DUAL_IP_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=str(DUAL_IP_STATE_FILE.parent), prefix=".dual_ip_state_", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True, default=str)
        os.replace(tmp_path, DUAL_IP_STATE_FILE)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _dual_ip_save_state():
    """Persist the current _dual_ip_pending/_dual_ip_context so a crash or
    restart doesn't lose an in-flight reinstall. Called after every state
    transition (submission, each poll pass, completion/clear)."""
    if not _dual_ip_pending and not _dual_ip_context:
        _dual_ip_write_raw({})
        return
    ctx = _dual_ip_context
    serializable_ctx = {}
    if ctx:
        serializable_ctx = {
            "path": str(ctx.get("path", "")),
            "reinstall_idxs": list(ctx.get("reinstall_idxs", [])),
            # JSON object keys must be strings; converted back to int on load.
            "action_rows": {str(k): v for k, v in (ctx.get("action_rows") or {}).items()},
        }
    _dual_ip_write_raw({"pending": _dual_ip_pending, "context": serializable_ctx})


def _dual_ip_load_state():
    """Restore _dual_ip_pending/_dual_ip_context from disk at startup.
    `df` is reconstructed by re-reading the saved workbook path; `ie_page`
    is left unset here and lazily fetched by do_dual_ip_poll_now() the
    first time it's actually needed post-restart."""
    global _dual_ip_pending, _dual_ip_context
    raw = _dual_ip_read_raw()
    if not raw:
        return
    pending = raw.get("pending") or {}
    ctx_raw = raw.get("context") or {}
    if not pending or not ctx_raw.get("path"):
        return
    try:
        df = pd.read_excel(ctx_raw["path"])
    except Exception as exc:
        print(f"  (Could not restore dual-IP tracking: source workbook unreadable — {exc})")
        return
    _dual_ip_pending = pending
    _dual_ip_context = {
        "df": df,
        "action_rows": {int(k): v for k, v in ctx_raw.get("action_rows", {}).items()},
        "reinstall_idxs": list(ctx_raw.get("reinstall_idxs", [])),
        "path": Path(ctx_raw["path"]),
        "ie_page": None,  # re-acquired lazily by do_dual_ip_poll_now()
    }
    running = sum(1 for e in pending.values() if e.get("state") == "running")
    print(f"  Restored {len(pending)} tracked dual-IP reinstall(s) from a previous session "
          f"({running} still running) — press \"P\" to check on them.")


def _dual_ip_clear():
    """Drop all in-memory AND persisted dual-IP tracking. Like
    pipeline_clear_entry(), this only stops tracking it — it does not touch
    Alto or cancel the underlying reinstall ticket."""
    global _dual_ip_pending, _dual_ip_context
    _dual_ip_pending = {}
    _dual_ip_context = {}
    _dual_ip_write_raw({})


# Restored here (module import time) rather than inside main(), so tracking
# is already populated the moment the script starts — no separate "load"
# step needed before option P works.
try:
    _dual_ip_load_state()
except Exception as exc:
    print(f"  (Dual-IP state restore skipped: {exc})")


def do_dual_ip_unreachable_workflow():
    path = max(Path.cwd().glob("dual_ip_tickets_*.xlsx"), key=lambda p: p.stat().st_mtime, default=None)
    if path is None:
        print("No dual_ip_tickets_*.xlsx found. Run option 1/6 (or E) first.")
        return

    df = pd.read_excel(path)
    if df.empty:
        print("Dual-IP workbook is empty.")
        return

    change_name = input("Aries NIC change name [Check 2NIC v1]: ").strip() or ARIES_NIC_CHANGE_NAME
    print(f"\nLoaded {len(df)} OS EIPv4/EIPv6 unreachable ticket(s).")

    confirm = input(
        f"Type RUN to start the OS EIPv4/EIPv6 workflow for all {len(df)} ticket(s): "
    ).strip().upper()
    if confirm != "RUN":
        print("Cancelled.")
        return

    ie_page = get_playwright_page(
        MAINTENANCE_LOOKUP_PAGE,
        prompt_label="ie-oci instance lookup page",
    )
    # One Aries session per distinct region present in this dual-IP export
    # (region column set by do_ticketq()/export_tickets_from_web()) — opened
    # lazily just before the NIC-check loop below, once we know which
    # tickets actually need it.
    aries_pages = {}

    all_results = {}

    # IMPORTANT: no batching here. This workflow intentionally runs all
    # selected tickets in one operation. Other menu workflows are untouched.
    resolved = _secondary_reachability_by_ticket(df, ie_page)

    action_rows = {}
    aries_candidates = []

    for idx, item in resolved.items():
        base = dict(item)

        if item.get("initial_reachable"):
            base["initial_action"] = "Verify & close"
            base["action"] = "Verify & close"
            base["final_status"] = "Reachable - verify & close"
        else:
            base["initial_action"] = "Run Aries NIC check"
            base["action"] = "Run Aries NIC check"
            base["final_status"] = ""
            aries_candidates.append(idx)

        action_rows[idx] = base

    if aries_candidates:
        print(
            f"\n{len(aries_candidates)} ticket(s) have ALL secondary IPs unreachable; "
            "running Aries NIC check."
        )

        for idx in aries_candidates:
            item = action_rows[idx]

            # Prefer secondary IPv6 for the Aries agent check, falling back to
            # secondary IPv4 when IPv6 is not available.
            nic_target = (
                item.get("secondary_ipv6")
                or item.get("secondary_ipv4")
                or ""
            ).split(",")[0].strip()

            if not nic_target:
                item["action"] = "OCI lookup failed - manual investigation"
                item["final_status"] = "No secondary IP"
                continue

            nic_region = _row_aries_region(df.loc[idx])
            if nic_region not in aries_pages:
                aries_pages[nic_region] = get_aries_page(nic_region)
            nic = run_aries_nic_check(nic_target, aries_pages[nic_region], change_name, region=nic_region)
            item.update(nic)

            if nic.get("aries_nic_classification") == "no_carrier":
                # Explicit NO-CARRIER = immediate Recreate.
                item["action"] = "Recreate (NIC NO-CARRIER)"
            else:
                # Any completed NIC result other than explicit NO-CARRIER
                # follows the agreed Reinstall -> post-check -> Recreate path.
                item["action"] = "Reinstall (no NIC NO-CARRIER)"

    recreate_idxs = [
        idx for idx, item in action_rows.items()
        if item.get("action") == "Recreate (NIC NO-CARRIER)"
    ]
    reinstall_idxs = [
        idx for idx, item in action_rows.items()
        if item.get("action") == "Reinstall (no NIC NO-CARRIER)"
    ]

    # Explicit NO-CARRIER -> Recreate.
    if recreate_idxs:
        ips = [
            _dual_ticket_primary_ipv6(df.loc[idx])
            for idx in recreate_idxs
        ]
        ips = [x for x in ips if x]

        if ips:
            print(
                f"\nRecreating {len(ips)} NIC-NO-CARRIER instance(s)..."
            )
            rr = run_recreates(ips, confirm=False)

            for idx in recreate_idxs:
                ip = _dual_ticket_primary_ipv6(df.loc[idx])
                r = rr.get(ip, {})

                action_rows[idx].update({
                    "recreate_status": r.get("status", ""),
                    "recreate_ticketId": r.get("ticketId", ""),
                    "recreate_ticketUrl": r.get("ticketUrl", ""),
                })

                action_rows[idx]["final_status"] = (
                    "Recreate submitted"
                    if r.get("status") == "Submitted"
                    else "Recreate submission failed"
                )

    # No NO-CARRIER -> Reinstall -> wait -> SAOS secondary-IP recheck.
    #
    # This wait used to block here (via _wait_for_operation_results, a
    # sleep-loop that can run up to 15 minutes with no console output at
    # all). Instead, submit and hand off to _dual_ip_pending/_dual_ip_context
    # so menu option P can check in on it without blocking the rest of the
    # dashboard (2026-09-21 change).
    if reinstall_idxs:
        ips = [
            _dual_ticket_primary_ipv6(df.loc[idx])
            for idx in reinstall_idxs
        ]
        ips = [x for x in ips if x]

        if ips:
            print(
                f"\nReinstalling {len(ips)} no-NO-CARRIER instance(s)..."
            )
            ir = run_reinstalls(ips, confirm=False)

            for idx in reinstall_idxs:
                ip = _dual_ticket_primary_ipv6(df.loc[idx])
                r = ir.get(ip, {})
                action_rows[idx].update({
                    "reinstall_status": r.get("status", ""),
                    "reinstall_ticketId": r.get("ticketId", ""),
                    "reinstall_ticketUrl": r.get("ticketUrl", ""),
                })

            global _dual_ip_pending, _dual_ip_context
            _dual_ip_pending = {}
            for idx in reinstall_idxs:
                ip = _dual_ticket_primary_ipv6(df.loc[idx])
                r = ir.get(ip, {})
                ticket_url = str(r.get("ticketUrl", "") or "")
                ticket_id = str(r.get("ticketId", "") or "")
                if r.get("status") != "Submitted":
                    _dual_ip_pending[ip] = {
                        "state": "submit_failed",
                        "detail": r.get("message", r.get("status", "")),
                    }
                else:
                    _dual_ip_pending[ip] = {
                        "state": "running", "detail": "",
                        "ticket_url": ticket_url, "ticket_id": ticket_id,
                        "domain": pipeline_alto_domain_from_ticket_url(ticket_url),
                    }

            _dual_ip_context = {
                "df": df, "action_rows": action_rows,
                "reinstall_idxs": reinstall_idxs,
                "path": path, "ie_page": ie_page,
            }
            _dual_ip_save_state()

            print(
                f"\n{len(reinstall_idxs)} reinstall(s) submitted — running in "
                "the background, ticket link(s):"
            )
            for ip, e in _dual_ip_pending.items():
                print(f"  {ip} -> {e.get('ticket_url') or '(no ticket url — submit may have failed)'}")
            print(
                "Keep using the dashboard as normal — press \"P\" any time to "
                "check on these; once they've all settled, P will run the "
                "post-reinstall SAOS recheck, recreate anything still "
                "unreachable, and save/open the final workbook."
            )
            return

    # Reached only when there was nothing to reinstall (everything was either
    # already reachable or NO-CARRIER->recreate) — nothing pending, so finish
    # and save right away, same as the original synchronous behavior.
    all_results.update(action_rows)

    out = (
        path.parent
        / f"dual_ip_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    )
    build_dual_ip_workbook(df, all_results, path.name).save(out)

    print(f"\nSaved: {out}")
    open_file(out)
    print("\nOS EIPv4/EIPv6 workflow complete.")


def do_dual_ip_poll_now():
    """Non-blocking check-in for reinstall(s) submitted by the OS EIPv4/EIPv6
    workflow (menu N). Does ONE poll pass per pending ticket — no sleeping,
    no loop — so it's safe to call from menu option P repeatedly while you
    keep using the rest of the dashboard in between. Once every pending
    reinstall has settled (finished/failed/timed out), runs the
    post-reinstall SAOS recheck, recreates anything still unreachable, and
    saves/opens the final workbook — the same tail end the original
    synchronous workflow ran inline."""
    global _dual_ip_pending, _dual_ip_context

    if not _dual_ip_pending:
        return

    active = [ip for ip, e in _dual_ip_pending.items() if e.get("state") == "running"]
    if active:
        print(f"\nDual-IP: polling {len(active)} in-flight reinstall(s)...")
        for ip in active:
            e = _dual_ip_pending[ip]
            if not e.get("domain") or not e.get("ticket_id"):
                e["state"] = "unknown"
                e["detail"] = "Submitted operation has no ticketUrl/ticketId"
                print(f"    {ip}: unknown — no ticketUrl/ticketId")
                continue
            try:
                page = get_alto_page(e["domain"], sample_ticket_url=e["ticket_url"],
                                      prompt_label=f"Alto page ({e['domain']})")
                result = alto_poll_ticket_status(page, e["ticket_id"])
            except Exception as exc:
                print(f"    {ip}: poll error — {exc} (left as-is, try again later)")
                continue
            state = result.get("state")
            if state in ("finished", "failed", "awaiting_review"):
                e["state"] = state
                e["detail"] = result.get("detail", "")
            print(f"    {ip}: {e['state']} ({e.get('detail') or 'no detail yet'})")
        _dual_ip_save_state()

    still_running = [ip for ip, e in _dual_ip_pending.items() if e.get("state") == "running"]
    if still_running:
        print(f"Dual-IP: {len(still_running)} still running — check again later with \"P\".")
        return

    print("\nDual-IP: all pending reinstall(s) have settled — running post-reinstall SAOS recheck...")

    ctx = _dual_ip_context
    df = ctx["df"]; action_rows = ctx["action_rows"]
    reinstall_idxs = ctx["reinstall_idxs"]; path = ctx["path"]; ie_page = ctx["ie_page"]
    if ie_page is None:
        # Restored from disk after a restart — the original page is gone
        # along with the process that owned it; get a fresh one.
        print("  (Restored session — re-authenticating ie-oci page...)")
        ie_page = get_playwright_page(
            MAINTENANCE_LOOKUP_PAGE, prompt_label="ie-oci instance lookup page"
        )
        ctx["ie_page"] = ie_page

    for idx in reinstall_idxs:
        ip = _dual_ticket_primary_ipv6(df.loc[idx])
        st = _dual_ip_pending.get(ip, {})
        action_rows[idx].update({
            "reinstall_operation_state": st.get("state", ""),
            "reinstall_operation_detail": st.get("detail", ""),
        })

    # Re-resolve OCI secondary IPv4/IPv6 after reinstall, then test BOTH
    # populated secondary address types through the existing SAOS port-22
    # checker. Any reachable address is a pass.
    post_resolved = _secondary_reachability_by_ticket(df.loc[reinstall_idxs].copy(), ie_page)
    post_recreate = []

    for idx in reinstall_idxs:
        post = post_resolved.get(idx, {})
        action_rows[idx].update({
            "post_reinstall_secondary_ipv4": post.get("secondary_ipv4", ""),
            "post_reinstall_secondary_ipv6": post.get("secondary_ipv6", ""),
            "post_reinstall_saos_results": post.get("initial_secondary_results", ""),
            "post_reinstall_reachable": post.get("initial_reachable", False),
        })
        if post.get("initial_reachable"):
            action_rows[idx]["final_status"] = "Reachable after reinstall - verify & close"
        else:
            post_recreate.append(idx)
            action_rows[idx]["action"] = "Recreate (still unreachable after reinstall)"

    # Still unreachable after reinstall -> Recreate.
    if post_recreate:
        ips = [_dual_ticket_primary_ipv6(df.loc[idx]) for idx in post_recreate]
        ips = [x for x in ips if x]

        if ips:
            print(f"\nPost-reinstall SAOS still unreachable: recreating {len(ips)} instance(s)...")
            rr2 = run_recreates(ips, confirm=False)

            for idx in post_recreate:
                ip = _dual_ticket_primary_ipv6(df.loc[idx])
                r = rr2.get(ip, {})
                action_rows[idx].update({
                    "recreate_after_reinstall_status": r.get("status", ""),
                    "recreate_after_reinstall_ticketId": r.get("ticketId", ""),
                    "recreate_after_reinstall_ticketUrl": r.get("ticketUrl", ""),
                })
                action_rows[idx]["final_status"] = (
                    "Recreate submitted after failed post-reinstall check"
                    if r.get("status") == "Submitted"
                    else "Recreate submission failed after reinstall"
                )

    out = path.parent / f"dual_ip_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    build_dual_ip_workbook(df, action_rows, path.name).save(out)

    print(f"\nSaved: {out}")
    open_file(out)
    print("\nOS EIPv4/EIPv6 workflow complete.")

    _dual_ip_clear()


# ============================================================
# NEW (2026-09-16): MAINTENANCE PRECHECK -> ARIES DISK CHECK -> SR FLAGGING
# ============================================================
# TEST-KEY WORKFLOW (menu option "D"). Kept fully separate from the
# production reboot/reinstall/recreate pipeline above so it can be
# exercised end-to-end against real disk/NVMe-lost tickets before being
# folded into anything auto-submitted. See DISK_LOST_DETAIL_KEYWORDS /
# the disk_lost_tickets_*.xlsx workbook (written by do_ticketq()) for
# where these tickets currently land.
#
# CONFIRMED PIPELINE (as agreed, 2026-09-16):
#   1. For each disk-lost ticket's IP, query the maintenance batch_list
#      API. If the MOST RECENT event (by updateTime) has lifecycleState
#      == "SCHEDULED" -> flag for the existing Recreate pipeline (NOT
#      auto-submitted here — surfaced for manual confirmation via
#      option 5, same escalation style as the rest of this dashboard).
#   2. Otherwise -> run the Aries NVMe-count-check script against that
#      IP (precheck, then deploy), poll its taskdetail, and classify:
#      agent_lost / missing_drive / unrecognized_shape / generic
#      failure / pass.
#   3. missing_drive results get grouped by (tenancy, region) via the
#      instance batch_list API, and a Lark-Base "SR Ticketing" form
#      draft is assembled per group (NOT auto-submitted — printed for
#      manual review/paste, per the user's request to test this path
#      first).
#
# STILL UNCONFIRMED (flagged inline where relevant — first working pass,
# not a verified end-to-end integration yet):
#   - Whether a single Aries deployment call genuinely accepts >1 IP at
#     once. The payload's targetIPs field is an array (schema looks
#     multi-IP capable) but every real example captured so far only had
#     one IP in it — this code still submits one IP per deployment call
#     until that's tested.
#   - The exact JSON shape of the deployment POST *response* — only the
#     request payload was captured, never a real response body.
#     aries_deploy() prints the raw response so the field names it
#     guesses at (id/deploymentID/jobs/jobID) can be corrected.
#   - Whether a passing (non-"failed") task uses status=success or
#     something else on the taskdetail query string — only ever
#     confirmed with status=failed.
#   - agent_lost / unrecognized_shape / generic_failure are classified
#     and printed but have no further manual-outcome action wired yet —
#     only missing_drive goes all the way to an SR draft, per the
#     user's request to validate that branch first.
# ============================================================

MAINTENANCE_BATCH_LIST_API = "https://ie-oci.tiktok-row.net/api/maintenance/batch_list"
INSTANCE_BATCH_LIST_API = "https://ie-oci.tiktok-row.net/api/instance/batch_list"

# Landing page opened for the D-workflow maintenance lookup (distinct from the
# reboot/reinstall operation pages — this is the instance batch-query view).
MAINTENANCE_LOOKUP_PAGE = (
    "https://ie-oci.tiktok-row.net/batch_query"
    "?resource=instance&identifiedBy=ip&freshness=latest"
)

ARIES_POLL_TIMEOUT_SECONDS = 60
ARIES_POLL_INTERVAL_SECONDS = 5
ARIES_FETCH_RETRIES = 3
ARIES_MAINTAINER = "edwinlim.rciw"  # confirmed fixed to this account for now — flag if that ever changes

# Aries is deployed separately per region, and — confirmed the hard way via a
# real 404, 2026-09-23 — the FRONTEND page and the API BACKEND for EUTTP live
# on two entirely different domains, not just a "-eu" variant of one domain:
#   frontend (login, modificationList pages): https://aries-eu.tiktok-row.org
#   API backend (/app/v1/... routes):          https://aries.tiktok-eu.org
# The API host was confirmed via a real captured request URL:
#   GET https://aries.tiktok-eu.org/app/v1/deployment/{id}
# i18n's frontend and API happen to share one host (aries.tiktok-row.org),
# which is why this split was invisible until EUTTP exposed it. Each region
# also has its OWN unitID + script "version" string per check type (Aries-
# internal script identifiers, not our own versioning) — confirmed real via
# captured EUTTP deployment responses (2026-09-23): unitID "185" for both
# disk and NIC checks, disk version "check NVMEs" (no "v1.1" suffix, unlike
# i18n's), NIC version "check NIC state" (identical string to i18n's).
# unitName "DCS BPO check scripts" is informational only — not sent in our
# request payload, same as i18n. The deployment-detail page URL pattern
# ({base}/modification/modificationList/{deployment_id}) and both scripts'
# bodies are CONFIRMED IDENTICAL to i18n's.
# STILL INFERRED, NOT DIRECTLY CAPTURED: the precheck and taskdetail paths
# under aries.tiktok-eu.org (only GET .../deployment/{id} has been directly
# observed there) — assumed to follow the same /app/v1/... route family as
# the confirmed deploy-detail GET, since that's the one piece of this API
# actually seen live. If precheck or taskdetail still 404s against this API
# host, that assumption is what to check next.
ARIES_REGION_CONFIG = {
    "i18n": {
        "base": "https://aries.tiktok-row.org",
        "api_base": "https://aries.tiktok-row.org",
        "disk_unit_id": "475",
        "disk_script_version": "check NVMEs v1.1",
        "nic_unit_id": "475",
        "nic_script_version": "check NIC state",
        "nic_confirmed": True,
    },
    "euttp": {
        "base": "https://aries-eu.tiktok-row.org",
        "api_base": "https://aries.tiktok-eu.org",
        "disk_unit_id": "185",
        "disk_script_version": "check NVMEs",
        "nic_unit_id": "185",
        "nic_script_version": "check NIC state",
        "nic_confirmed": True,
    },
}


def aries_region_base(region: str) -> str:
    """Frontend page host — for browser navigation / login / human-visitable
    deployment links. NOT necessarily where the API lives (see api_base)."""
    return ARIES_REGION_CONFIG[normalize_region(region)]["base"]


def aries_api_base(region: str) -> str:
    """API backend host — for precheck/deploy/taskdetail fetch() calls."""
    return ARIES_REGION_CONFIG[normalize_region(region)]["api_base"]


def _aries_domain_to_region(domain: str) -> str:
    """Reverse-lookup: which region does this domain belong to (as either
    its frontend or its API host)? Used to key captured auth headers by
    region rather than by domain, since a region's frontend and API can be
    on different domains (EUTTP) or the same one (i18n)."""
    for region, cfg in ARIES_REGION_CONFIG.items():
        if domain in (urlparse(cfg["base"]).netloc, urlparse(cfg["api_base"]).netloc):
            return region
    return "i18n"


def aries_precheck_api(region: str) -> str:
    return f"{aries_api_base(region)}/app/v1/deployment/precheck"


def aries_deploy_api(region: str) -> str:
    return f"{aries_api_base(region)}/app/v1/deployment"


def aries_taskdetail_api(region: str) -> str:
    return f"{aries_api_base(region)}/app/v1/taskdetail"


def aries_launch_page(region: str) -> str:
    # Landing page opened when authenticating the Aries session — the script
    # launch view, on the FRONTEND host, so the user lands directly on the
    # change-launch page.
    return f"{aries_region_base(region)}/modification/modificationList/launch?maintainer={ARIES_MAINTAINER}"


# Backward-compatible i18n aliases — a couple of older comments/prints in
# this file still reference these flat names; keep them pointed at i18n so
# nothing silently breaks. New code should go through aries_region_base()
# and friends above instead.
ARIES_BASE = ARIES_REGION_CONFIG["i18n"]["base"]
ARIES_PRECHECK_API = aries_precheck_api("i18n")
ARIES_DEPLOY_API = aries_deploy_api("i18n")
ARIES_TASKDETAIL_API = aries_taskdetail_api("i18n")
ARIES_LAUNCH_PAGE = aries_launch_page("i18n")
ARIES_UNIT_ID = ARIES_REGION_CONFIG["i18n"]["disk_unit_id"]
ARIES_SCRIPT_VERSION = ARIES_REGION_CONFIG["i18n"]["disk_script_version"]

# Exact script body captured from a real "Disk Check" deployment — this is
# what actually runs on the target host, do not edit casually.
ARIES_NVME_CHECK_SCRIPT = r"""#!/usr/bin/env bash
set -euo pipefail

declare -A SHAPE_NVME_COUNTS=(
    ["BM.DenseIO.E5T-LM.192"]=12
    ["BM.DenseIO.E4.128"]=8
    ["BM.Standard2T.E4-WB.128"]=2
    ["BM.Standard.E5T.192"]=4
    ["BM.Standard2T.E4.128"]=2
    ["BM.DenseIO.E5T.128"]=11
    ["BM.Standard.E5T-LM.192.v2"]=3
    ["BM.DenseIO2.52"]=8
    ["BM.Standard.E5T-LM.192"]=2
)

if [[ $EUID -ne 0 ]]; then
    echo "please run this script as root" >&2
    exit 1
fi

if [[ -n "$(ip -4 -o addr show dev eth0 2>/dev/null)" ]]; then
    shape_url="http://169.254.169.254/opc/v2/instance/shape"
else
    shape_url="http://[fd00:c1::a9fe:a9fe]/opc/v2/instance/shape"
fi

if ! shape=$(curl -g -fsSL --connect-timeout 5 --max-time 15 \
    -H "Authorization: Bearer Oracle" "$shape_url"); then
    echo "failed to get instance shape" >&2
    exit 1
fi
shape=$(printf '%s' "$shape" | tr -d '"\r\n')
if [[ -z "$shape" ]]; then
    echo "instance shape is empty" >&2
    exit 1
fi

expected="${SHAPE_NVME_COUNTS[$shape]:-}"
if [[ -z "$expected" ]]; then
    echo "shape $shape is not in the list, please notify SRE to add it" >&2
    exit 1
fi

HOSTSN=$(dmidecode -s system-serial-number)
echo "host serial: $HOSTSN"

if ! command -v nvme >/dev/null 2>&1; then
    apt install -y nvme-cli
fi

if ! nvme_output=$(nvme list); then
    echo "nvme list failed" >&2
    exit 1
fi

mapfile -t devices < <(
    printf '%s\n' "$nvme_output" |
        awk '$1 ~ /^\/dev\/nvme[0-9]+n1$/ {print $1}' |
        sort -u
)

declare -A found=()
for device in "${devices[@]}"; do
    found["$device"]=1
done

missing=()
for ((i = 0; i < expected; i++)); do
    device="/dev/nvme${i}n1"
    if [[ -z "${found[$device]:-}" ]]; then
        missing+=("$device")
    fi
done

actual=${#devices[@]}
printf 'Shape: %s\nExpected NVMe count: %d\nActual NVMe count: %d\n' \
    "$shape" "$expected" "$actual"

if ((${#missing[@]} > 0)); then
    echo "Missing NVMe devices:"
    printf '  %s\n' "${missing[@]}"
fi

echo ""
echo ""
echo "nvme list:"
echo "$nvme_output"

if ((actual != expected || ${#missing[@]} > 0)); then
    exit 1
fi

echo "OK: all expected NVMe devices are present"
"""

# Airport-code region labels used by the SR Ticketing form's "Impacted
# Region" dropdown — NOT the same as OCI's own region strings. Only the
# three marked CONFIRMED are verified against real host data; the rest
# are the dropdown's other listed options, included as best-guess OCI
# region mappings — verify before relying on them.
REGION_AIRPORT_CODE = {
    "us-ashburn-1": "IAD",    # CONFIRMED (2026-09-16, real host)
    "us-dallas-1": "DFW",     # CONFIRMED (2026-09-16, real host)
    "ap-tokyo-1": "NRT",      # CONFIRMED (2026-09-16, real host)
    # Unconfirmed guesses:
    "us-chicago-1": "ORD",
    "us-phoenix-1": "PHX",
    "ap-sydney-1": "SYD",
    "eu-frankfurt-1": "FRA",
    "us-portland-1": "PDX",
    "eu-amsterdam-1": "AMS",
    # "FYV" seen in the dropdown but no candidate OCI region identified yet.
}

SR_FIXED_IMPACTED_SERVICE = "OCI Compute"
# NOTE: confirmed via a real Playwright codegen capture (2026-09-17) that the
# actual Lark dropdown option text has a space before "/P2" — the previous
# value here ("Severity 3/P2 - Technical Issue", no space) would NOT match
# that option via has_text filtering. Fixed to match exactly what's on the
# form.
SR_FIXED_SEVERITY = "Severity 3 /P2 - Technical Issue"


# ---- Aries session (separate auth from the ie-oci JWT machinery above) ----
_aries_pages = {}  # region ("i18n"/"euttp") -> page
# region -> {lowercased header name: value}, e.g. "x-aries-token". Keyed per
# region, not per domain (bug fixed 2026-09-23 in two stages: first to stop
# an i18n and a EUTTP session clobbering one flat dict, then again once
# EUTTP turned out to have a separate frontend domain
# (aries-eu.tiktok-row.org) from its API domain (aries.tiktok-eu.org) —
# keying by "the domain a request hit" would then miss tokens sent to the
# API host entirely. _aries_domain_to_region() maps either domain to its
# region so lookups work regardless of how many hosts a region spans.
_aries_headers = {}


def get_aries_page(region: str = "i18n", prompt_label: str = "Aries page"):
    """Authenticated page for the given region's Aries frontend, reusing one
    tab per region across calls (same persistent-browser-profile pattern as
    get_alto_page()) — so an i18n and a EUTTP Aries session can both be open
    at once without clobbering each other. Watches network traffic for the
    'x-aries-token' header — the site's own session-scoped token, distinct
    from the PaaS 'x-jwt-token' that get_playwright_page()'s global listener
    already captures. Captured tokens are filed by region (via
    _aries_domain_to_region()), not by the domain the request happened to hit
    — EUTTP's frontend (aries-eu.tiktok-row.org) and API backend
    (aries.tiktok-eu.org) are different domains, so keying by "the page's
    domain" would silently miss tokens sent to the API host."""
    _ensure_browser_context()
    region = normalize_region(region)

    if region in _aries_pages:
        try:
            _aries_pages[region].evaluate("() => true")
            return _aries_pages[region]
        except Exception:
            _aries_pages.pop(region, None)

    page = _context.new_page()
    _aries_pages[region] = page

    def _on_request(request):
        try:
            req_region = _aries_domain_to_region(urlparse(request.url).netloc)
            for hk, hv in request.headers.items():
                if hk.lower() in ("x-aries-token", "x-jwt-token") and hv:
                    _aries_headers.setdefault(req_region, {})[hk.lower()] = hv.strip()
        except Exception:
            pass

    page.on("request", _on_request)

    target_url = aries_launch_page(region)
    print(f"\nOpening {target_url}")
    print("→ If you are not logged in to Aries yet, log in now.")
    try:
        page.goto(target_url, wait_until="domcontentloaded", timeout=60000)
    except Exception as e:
        print(f"  Navigation note: {e}")

    deadline = time.time() + 30
    while time.time() < deadline and "x-aries-token" not in _aries_headers.get(region, {}):
        time.sleep(0.5)

    if "x-aries-token" in _aries_headers.get(region, {}):
        print("  Aries session detected.")
    else:
        print("  Warning: x-aries-token not observed yet — click around (e.g. open")
        print("  Change List) to trigger a real API call and capture it.")

    input(f"\n>>> Press ENTER after the {prompt_label} is ready... ")
    return page


def _same_ip(a, b) -> bool:
    """Compare two IPs tolerant of formatting differences (IPv6 compression,
    case, brackets/whitespace). EUTTP hosts are frequently addressed by IPv6
    (fdbd:...), and Aries may echo the address back in a different textual
    form than we submitted — a plain string == would then never match and the
    poll would end as 'no_task_data' even though the task ran."""
    import ipaddress
    x, y = str(a or "").strip().strip("[]"), str(b or "").strip().strip("[]")
    if x == y:
        return True
    try:
        return ipaddress.ip_address(x) == ipaddress.ip_address(y)
    except ValueError:
        return x.lower() == y.lower()


def _aries_fetch(page, url: str, method: str = "GET", payload: dict = None) -> dict:
    """Calls Aries' API with the browser session's cookies plus whatever
    x-aries-token / x-jwt-token headers have actually been observed (never
    fabricated). Which region's captured headers to send is resolved from
    the request URL's domain via _aries_domain_to_region().

    Two transports, chosen by origin:
      - SAME origin as the open page (i18n: frontend and API share one host)
        -> in-page fetch(), as before, so the aries-session cookie attaches
        naturally.
      - CROSS origin (EUTTP: page on aries-eu.tiktok-row.org, API on
        aries.tiktok-eu.org) -> Playwright's request client (page.request),
        which shares the browser context's cookies but is NOT subject to
        CORS. Added 2026-09-28 after an in-page fetch to the EUTTP API host
        failed every attempt with "TypeError: Failed to fetch" (the browser
        blocking a cross-origin call, not an HTTP error). Origin/Referer are
        set to the page's origin so the API sees what the real UI sends."""
    region_key = _aries_domain_to_region(urlparse(url).netloc)
    headers = dict(_aries_headers.get(region_key, {}))
    page_origin = ""
    try:
        pu = urlparse(page.url)
        page_origin = f"{pu.scheme}://{pu.netloc}" if pu.netloc else ""
    except Exception:
        pass
    url_origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    cross_origin = bool(page_origin) and page_origin != url_origin

    response = None
    last_error = None
    for attempt in range(1, ARIES_FETCH_RETRIES + 1):
        try:
            if cross_origin:
                req_headers = {"accept": "application/json"}
                req_headers.update(headers)
                req_headers["origin"] = page_origin
                req_headers["referer"] = page_origin + "/"
                kwargs = {"method": method, "headers": req_headers, "timeout": 60000}
                if payload is not None:
                    req_headers["content-type"] = "application/json; charset=utf-8"
                    kwargs["data"] = json.dumps(payload)
                api_resp = page.request.fetch(url, **kwargs)
                response = {"status": api_resp.status, "body": api_resp.text()}
            else:
                response = page.evaluate(
                    """async ({url, method, payload, headers}) => {
                        const opts = {
                            method,
                            credentials: 'include',
                            headers: Object.assign({'accept': 'application/json'}, headers),
                        };
                        if (payload !== null) {
                            opts.headers['content-type'] = 'application/json; charset=utf-8';
                            opts.body = JSON.stringify(payload);
                        }
                        const res = await fetch(url, opts);
                        const text = await res.text();
                        return { status: res.status, body: text };
                    }""",
                    {"url": url, "method": method, "payload": payload, "headers": headers},
                )
            break
        except Exception as exc:
            last_error = exc
            if attempt < ARIES_FETCH_RETRIES:
                print(f"    Aries fetch failed (attempt {attempt}/{ARIES_FETCH_RETRIES}, "
                      f"{'cross-origin request client' if cross_origin else 'in-page fetch'}); retrying...")
                if not cross_origin:
                    try:
                        page.reload(wait_until="domcontentloaded", timeout=60000)
                    except Exception:
                        pass
                time.sleep(attempt * 2)

    if response is None:
        return {
            "_error": f"Aries fetch failed after {ARIES_FETCH_RETRIES} attempts: {last_error}",
            "_url": url,
        }

    status = response.get("status")
    body_text = response.get("body", "")
    if status != 200:
        return {"_error": f"HTTP {status} from {url}", "_status": status, "_url": url, "_body": body_text[:300]}
    try:
        return json.loads(body_text)
    except json.JSONDecodeError:
        return {"_error": "bad JSON", "_body": body_text[:300]}


# ---- ie-oci maintenance / instance lookups (reuses the existing JWT
# capture machinery — same headers as reboot/reinstall/recreate) --------

def _ie_oci_batch_fetch(page, url: str, ips: list, extra_payload: dict) -> dict:
    captured_clean = _sanitize_jwt_map(_captured_jwt_headers)
    payload = {"identifiedBy": "ip", "freshness": "latest", "ips": list(ips), **extra_payload}
    response = page.evaluate(
        """async ({url, payload, captured}) => {
            const headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/plain, */*'};
            for (const [k, v] of Object.entries(captured)) headers[k] = v;
            const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(payload) });
            const text = await res.text();
            return { status: res.status, body: text };
        }""",
        {"url": url, "payload": payload, "captured": captured_clean},
    )
    status = response.get("status")
    body_text = response.get("body", "")
    if status != 200:
        return {"_error": f"HTTP {status}", "_body": body_text[:300]}
    try:
        return json.loads(body_text)
    except json.JSONDecodeError:
        return {"_error": "bad JSON", "_body": body_text[:300]}


def maintenance_batch_list(page, ips: list) -> dict:
    """POST /api/maintenance/batch_list. Confirmed 2026-09-16 — NOTE: does
    NOT return a hit for every queried IP (absent = no event on record)."""
    return _ie_oci_batch_fetch(page, MAINTENANCE_BATCH_LIST_API, ips, {"ocids": [], "instanceIds": []})


def instance_batch_list(page, ips: list) -> dict:
    """POST /api/instance/batch_list. Confirmed 2026-09-16 — unlike
    maintenance_batch_list, this returns a hit for every queried IP."""
    return _ie_oci_batch_fetch(page, INSTANCE_BATCH_LIST_API, ips, {"ocids": [], "hostSerials": []})


def pick_latest_maintenance_state(events: list) -> dict:
    """Given the maintenance batch_list data[] entries for ONE ip (there
    can be several — e.g. one SCHEDULED + one CANCELED for the same
    fault), pick the most recent by updateTime. Per user decision
    2026-09-16: most-recent-by-updateTime wins, not 'any SCHEDULED'."""
    if not events:
        return {"lifecycleState": None, "event": None}
    latest = max(events, key=lambda e: e.get("updateTime", ""))
    return {"lifecycleState": latest.get("lifecycleState"), "event": latest}


# ---- Aries deployment (precheck + deploy + taskdetail) --------------------

def _aries_deployment_payload(name: str, ip: str, region: str = "i18n", deploy_timeout: int = 200) -> dict:
    """Deployment payload for the NVMe-count-check script against a
    single IP — matches the real captured request shape exactly. See the
    'STILL UNCONFIRMED' note above re: whether targetIPs can hold >1 IP.
    unitID/version come from ARIES_REGION_CONFIG since EUTTP uses different
    values than i18n (confirmed via a real captured EUTTP response).
    deploy_timeout overrides deployStrategy.simple.control.timeout — this is
    Aries' own per-host script-execution timeout (seconds), separate from
    our ARIES_POLL_TIMEOUT_SECONDS (how long WE poll Aries' API for a
    terminal result). Defaults to 200, matching every real captured request
    seen so far; the NVMe-timeout/reset workflow (see
    NVME_TIMEOUT_RESET_DETAIL_KEYWORDS) uses 660 instead, per explicit
    confirmation (2026-09-23) that this field — not our poll loop — is what
    "stand-alone timeout" refers to."""
    cfg = ARIES_REGION_CONFIG[normalize_region(region)]
    return {
        "name": name,
        "unitType": "script",
        "deployStrategy": {
            "mode": "simple", "user": "root", "bizArea": "cn",
            "hostAnalysisStrategy": "enable", "jobHandleStrategy": "pauseWhenFailed",
            "executeConfig": {"taskPersistPolicy": "none", "taskResource": {"type": "middle"}},
            "simple": {
                "targetPSMIDs": ["0"],
                "filter": {},
                "stageConfigs": [{
                    "name": "100 %", "mode": "percent", "percent": 100,
                    "preManualCheck": False, "autoManualCheck": True,
                    "control": {"concurrence": 100}, "key": 0,
                    "autoManualCheckers": [], "preManualCheckers": [],
                }],
                "preManualCheck": False, "preManualCheckers": [],
                "autoManualCheck": True, "autoManualCheckers": [],
                "control": {
                    "hostAggregationDimensions": [], "hostScatteringDimensions": [],
                    "timeout": deploy_timeout, "postWait": 0, "maxFailNum": 100,
                    "concurrence": 10, "maxConcurrence": 10,
                },
                "targetIPs": [ip],
            },
        },
        "approveStrategy": {"approvalProcesses": [{"type": "psm"}]},
        "changeLevel": "L3", "changeScene": "read_only",
        "changeDesp": {"emergency": False},
        "spec": {
            "taskType": "shell",
            "shell": {"entry": "/bin/bash", "script": ARIES_NVME_CHECK_SCRIPT},
            "paramEncryption": False,
        },
        "extra": {"changeApply": {"id": "", "platform": "SpaceX"}},
        "unitID": cfg["disk_unit_id"],
        "version": cfg["disk_script_version"],
    }


def aries_precheck(page, name: str, ip: str, region: str = "i18n", deploy_timeout: int = 200) -> dict:
    return _aries_fetch(page, aries_precheck_api(region), "POST", _aries_deployment_payload(name, ip, region, deploy_timeout))


def aries_deploy(page, name: str, ip: str, region: str = "i18n", deploy_timeout: int = 200) -> dict:
    return _aries_fetch(page, aries_deploy_api(region), "POST", _aries_deployment_payload(name, ip, region, deploy_timeout))


def aries_taskdetail(page, deployment_id: str, job_id: str = "", status: str = "", region: str = "i18n") -> dict:
    """GET /app/v1/taskdetail for a deployment.

    Query by deployment_id alone by default — the taskdetail response carries
    the jobID for each host, so we do NOT need job_id up front (the deploy
    response doesn't reliably expose it). Previously this hard-coded
    status=failed, which meant a PASSING host returned zero rows and the poller
    then timed out / mislabelled it — so status is now optional and omitted by
    default to return the entry regardless of pass/fail.
    """
    params = []
    if status:
        params.append(f"status={status}")
    params.append(f"deployment_id={deployment_id}")
    if job_id:
        params.append(f"job_id={job_id}")
    params.extend(["page=1", "page_size=100"])
    url = f"{aries_taskdetail_api(region)}?{'&'.join(params)}"
    return _aries_fetch(page, url, "GET")


def aries_deployment_detail(page, deployment_id: str, region: str = "i18n") -> dict:
    """GET /app/v1/deployment/{id} — the deployment-level record (confirmed
    real on the EUTTP API host, 2026-09-28). Used for diagnostics: its
    `status` shows whether the deployment ever left 'init'."""
    return _aries_fetch(page, f"{aries_deploy_api(region)}/{deployment_id}", "GET")


def _aries_no_data_diagnostics(page, deployment_id: str, region: str, last_task) -> str:
    """One-line explanation of WHY polling found nothing, so a silent
    no_task_data becomes actionable: the deployment's own status, plus the
    raw taskdetail reply (an HTTP 200 can still carry code != 0 + a msg, or
    an empty data[] because the deployment never started, or entries whose
    status/ip fields don't look like we expect)."""
    bits = []
    try:
        dd = aries_deployment_detail(page, deployment_id, region)
        if "_error" in dd:
            bits.append(f"deployment GET error: {dd.get('_error')}")
        else:
            d = dd.get("data") or {}
            bits.append(f"deployment status={d.get('status')!r} curPhaseIdx={d.get('curPhaseIdx')!r}")
    except Exception as exc:  # diagnostics must never raise
        bits.append(f"deployment GET raised: {exc}")
    try:
        raw = json.dumps(last_task, ensure_ascii=False, default=str)
    except Exception:
        raw = str(last_task)
    bits.append(f"last taskdetail reply: {raw[:500]}")
    return " | ".join(bits)


def _aries_status_kind(status) -> str:
    """Bucket a task `status` into 'failed' / 'success' / 'pending'.

    i18n reports plain 'failed' / 'success' / 'finished', but EUTTP was
    confirmed (2026-09-28, from a real taskdetail reply) to use
    'checkSuccess' for a passing host — which the old exact-match lists
    never recognised, so polling ran out its timeout even though the result
    was sitting in the API. Matching on the meaning ('fail…' / 'success…')
    instead of exact spellings handles both regions, and the probable
    'checkFailed' counterpart, without another round trip. Anything else
    (init, running, checking, …) is 'pending'."""
    s = str(status or "").strip().lower()
    if not s:
        return ""
    if "fail" in s or s in ("error", "timeout", "lost", "agentlost", "agent_lost",
                            "canceled", "cancelled", "aborted"):
        return "failed"
    if "success" in s or "succeed" in s or s in ("finished", "done", "complete", "completed"):
        return "success"
    return "pending"


def _aries_status_terminal(status) -> bool:
    return _aries_status_kind(status) in ("failed", "success")


def _refetch_failed_entry(page, deployment_id, entry: dict, ip: str, region: str) -> dict:
    """Re-query a finished host the way the Aries UI does (deployment_id +
    job_id, plus the task's own status word for failures) and prefer that
    entry when it has more to offer. Triggers when the host FAILED (the
    confirmed i18n UI request for full error output is status=failed with
    job_id) or when the polled entry came back with NO stdout/stderr at all
    (added 2026-09-28: the unfiltered poll is what returns stdout for a
    passing host on i18n, but nothing had confirmed the EUTTP API does the
    same for our exact query, so this is the safety net). Falls back to the
    polled entry if the re-query finds nothing better."""
    try:
        failed = _aries_status_kind(entry.get("status", "")) == "failed"
        no_output = not (str(entry.get("stdout", "") or "").strip()
                         or str(entry.get("stderr", "") or "").strip())
        if not (failed or no_output):
            return entry
        job = entry.get("jobID") or entry.get("jobId") or ""
        if not job and not failed:
            return entry  # nothing to narrow the query with
        rich = aries_taskdetail(page, str(deployment_id), str(job),
                                status=str(entry.get("status", "")) if failed else "",
                                region=region)
        if "_error" in rich:
            return entry
        for cand in (rich.get("data") or []):
            if _same_ip(cand.get("ip", ""), ip):
                if failed or str(cand.get("stdout", "") or "").strip() or str(cand.get("stderr", "") or "").strip():
                    return cand
    except Exception:
        pass
    return entry


def classify_taskdetail_entry(entry: dict) -> dict:
    """Classify one taskdetail data[] entry per the FINALIZED rule
    (2026-09-16):
      errCode==1001 (or statusDetail.reason starts with 'Agent Lost
        Reason:') -> agent_lost
      errCode==1003 + 'is not in the list' in stdout/stderr -> unrecognized_shape
      errCode==1003 + 'Missing NVMe devices:' in stdout -> missing_drive
      any other failed status -> generic_failure
      anything else -> pass

    host_serial / shape / expected_count / actual_count / nvme_devices are
    parsed from stdout UNCONDITIONALLY (2026-09-22 fix) — a passing run's
    stdout carries exactly the same "host serial:" / "Shape:" / "Expected
    NVMe count:" / "Actual NVMe count:" / "nvme list:" lines as a failing
    one, just with actual==expected and no "Missing NVMe devices:" block.
    Previously these were only parsed inside the `status == "failed"`
    branch, so a passing host's classification result — and everything
    downstream that reads it (the console print, the Excel aries_detail
    column) — came back with those fields blank even though the info was
    right there in stdout.
    """
    status = entry.get("status", "")
    err_code = entry.get("errCode")
    status_detail = entry.get("statusDetail") or {}
    reason = status_detail.get("reason", "") or ""
    stdout = entry.get("stdout", "") or ""
    stderr = entry.get("stderr", "") or ""

    result = {
        "classification": "pass",
        "status": status,
        "err_code": err_code,
        "host_serial": None,
        "shape": None,
        "expected_count": None,
        "actual_count": None,
        "missing_devices": [],
        "nvme_devices": [],
        "pass_message": None,
        "raw_reason": reason,
    }

    m_serial = re.search(r"host serial:\s*(\S+)", stdout)
    if m_serial:
        result["host_serial"] = m_serial.group(1)
    m_shape = re.search(r"^Shape:\s*(\S+)", stdout, re.MULTILINE)
    if m_shape:
        result["shape"] = m_shape.group(1)
    m_exp = re.search(r"Expected NVMe count:\s*(\d+)", stdout)
    if m_exp:
        result["expected_count"] = int(m_exp.group(1))
    m_act = re.search(r"Actual NVMe count:\s*(\d+)", stdout)
    if m_act:
        result["actual_count"] = int(m_act.group(1))
    # "nvme list:" table -> [{"device": "/dev/nvme0n1", "serial": "...", "model": "..."}, ...]
    # Present on both pass and fail; harmless/empty if the format ever shifts.
    for m in re.finditer(
        r"^(/dev/nvme\d+n\d+)\s+(\S+)\s+(.+?)\s{2,}", stdout, re.MULTILINE
    ):
        result["nvme_devices"].append(
            {"device": m.group(1), "serial": m.group(2), "model": m.group(3).strip()}
        )
    m_pass = re.search(r"^OK:.*$", stdout, re.MULTILINE)
    if m_pass:
        result["pass_message"] = m_pass.group(0).strip()

    # EUTTP reports a passing host as status "checkSuccess" (confirmed from a
    # real reply, 2026-09-28) and carries agent-loss in statusDetail.lostReason,
    # so decide by meaning (_aries_status_kind) rather than status == "failed".
    lost_reason = str(status_detail.get("lostReason", "") or "").strip()
    if _aries_status_kind(status) != "failed" and not lost_reason:
        return result

    if err_code == 1001 or reason.startswith("Agent Lost Reason:") or lost_reason:
        result["classification"] = "agent_lost"
        if lost_reason and not result["raw_reason"]:
            result["raw_reason"] = lost_reason
        return result

    if "is not in the list" in stdout or "is not in the list" in stderr:
        result["classification"] = "unrecognized_shape"
        return result

    if "Missing NVMe devices:" in stdout:
        result["classification"] = "missing_drive"
        result["missing_devices"] = re.findall(r"^\s*(/dev/nvme\d+n\d+)\s*$", stdout, re.MULTILINE)
        return result

    result["classification"] = "generic_failure"
    return result


def run_aries_disk_check(ip: str, aries_page, change_name: str, region: str = "i18n") -> dict:
    """Single-IP, all-in-one NVMe disk check: precheck -> deploy -> poll ->
    classify. Mirrors run_aries_nic_check()'s shape/behavior exactly (same
    poll-by-deployment_id-and-match-on-ip approach — no job_id needed up
    front), just against the NVMe-count-check script instead of the NIC
    one. Built for the standalone "check disks, run aries" shortcut, but
    has no dependency on that CLI wrapper — anything else needing a quick
    single-host disk check can call this directly too."""
    name = f"{change_name} - {ip}"
    rec = {
        "aries_change_run": name, "aries_change_run_link": "",
        "aries_deployment_id": "", "aries_job_id": "",
        "aries_status": "", "aries_classification": "", "aries_detail": "",
        "aries_host_serial": "", "aries_shape": "", "aries_missing_devices": "",
        "aries_expected_count": "", "aries_actual_count": "",
        "aries_stdout": "", "aries_stderr": "",
    }
    pre = aries_precheck(aries_page, name, ip, region)
    if "_error" in pre:
        rec["aries_status"] = "precheck_error"
        rec["aries_detail"] = str(pre.get("_error"))
        return rec
    dep = aries_deploy(aries_page, name, ip, region)
    if "_error" in dep:
        rec["aries_status"] = "deploy_error"
        rec["aries_detail"] = str(dep.get("_error"))
        return rec
    deployment_id = dep.get("id") or dep.get("deploymentID") or (dep.get("data") or {}).get("id")
    if not deployment_id:
        rec["aries_status"] = "deploy_incomplete"
        rec["aries_detail"] = "No deployment_id in Aries deploy response"
        return rec

    # Record the deployment id + a link right away, so even a run that never
    # produces task data leaves something to open in Aries and inspect.
    rec["aries_deployment_id"] = str(deployment_id)
    rec["aries_change_run_link"] = _aries_deployment_link(str(deployment_id), "", region)
    print(f"    Deployment created: {deployment_id}  ({rec['aries_change_run_link']})")

    deadline = time.time() + ARIES_POLL_TIMEOUT_SECONDS
    entry = None
    last_task = None
    while time.time() < deadline:
        task = aries_taskdetail(aries_page, str(deployment_id), region=region)  # unfiltered
        last_task = task
        if "_error" in task:
            rec["aries_status"] = "poll_error"
            rec["aries_detail"] = str(task.get("_error"))
            return rec
        matches = [x for x in (task.get("data") or []) if _same_ip(x.get("ip", ""), ip)]
        if not matches and len(task.get("data") or []) == 1:
            matches = list(task["data"])  # single-host deployment: the one entry is ours
        if matches and _aries_status_terminal(matches[0].get("status", "")):
            entry = matches[0]
            break
        time.sleep(ARIES_POLL_INTERVAL_SECONDS)

    if entry is None:
        rec["aries_status"] = "no_task_data"
        diag = _aries_no_data_diagnostics(aries_page, str(deployment_id), region, last_task)
        rec["aries_detail"] = f"No terminal task data after {ARIES_POLL_TIMEOUT_SECONDS}s | {diag}"
        print(f"    {rec['aries_detail']}")
        return rec
    entry = _refetch_failed_entry(aries_page, deployment_id, entry, ip, region)

    job_id = entry.get("jobID") or entry.get("jobId") or ""
    rec["aries_deployment_id"] = str(entry.get("deploymentID") or deployment_id)
    rec["aries_job_id"] = str(job_id)
    rec["aries_change_run_link"] = _aries_deployment_link(rec["aries_deployment_id"], rec["aries_job_id"], region)

    cr = classify_taskdetail_entry(entry)
    rec["aries_status"] = cr.get("status", "")
    rec["aries_classification"] = cr.get("classification", "")
    rec["aries_host_serial"] = cr.get("host_serial") or ""
    rec["aries_shape"] = cr.get("shape") or ""
    rec["_raw_reason"] = cr.get("raw_reason") or ""
    rec["aries_missing_devices"] = ", ".join(cr.get("missing_devices", []) or [])
    rec["aries_expected_count"] = "" if cr.get("expected_count") is None else cr.get("expected_count")
    rec["aries_actual_count"] = "" if cr.get("actual_count") is None else cr.get("actual_count")
    rec["aries_stdout"] = (entry.get("stdout") or "").strip()[:32000]
    rec["aries_stderr"] = (entry.get("stderr") or "").strip()[:32000]

    detail_bits = []
    if cr.get("raw_reason"):
        detail_bits.append(cr["raw_reason"])
    if cr.get("host_serial"):
        detail_bits.append(f"serial={cr['host_serial']}")
    if cr.get("shape"):
        detail_bits.append(f"shape={cr['shape']}")
    if cr.get("expected_count") is not None or cr.get("actual_count") is not None:
        detail_bits.append(f"expected={cr.get('expected_count')} actual={cr.get('actual_count')}")
    if rec["aries_missing_devices"]:
        detail_bits.append(f"missing={rec['aries_missing_devices']}")
    if cr.get("classification") == "pass" and cr.get("pass_message"):
        detail_bits.append(cr["pass_message"])
    rec["aries_detail"] = " | ".join(str(b) for b in detail_bits if b)
    return rec


def build_sr_groups(missing_drive_results: list, instance_lookup: dict) -> list:
    """Group missing_drive results by (tenancy, region) per user decision
    2026-09-16: an SR's OCIDs field only ever mixes hosts sharing the
    SAME tenancy AND region — otherwise split into separate SR drafts.
    missing_drive_results: [{"ip":..., "classification_result":...}, ...]
    instance_lookup: ip -> instance batch_list entry (tenancy/region/ocid)
    Returns a list of SR-form-shaped dicts (never submitted — for manual
    review/paste into the Lark Base form)."""
    groups = {}
    for item in missing_drive_results:
        ip = item["ip"]
        inst = instance_lookup.get(ip)
        if not inst:
            print(f"  WARNING: no instance data for {ip} — skipping SR grouping for this host.")
            continue
        key = (inst.get("tenancy", ""), inst.get("region", ""))
        groups.setdefault(key, []).append({**item, "instance": inst})

    sr_drafts = []
    for (tenancy, region), items in groups.items():
        region_code = REGION_AIRPORT_CODE.get(region, f"UNKNOWN({region})")
        ocids = [it["instance"].get("ocid", "") for it in items]
        host_lines = []
        for it in items:
            cr = it["classification_result"]
            classification = cr.get("classification", "generic_failure")
            devs = ", ".join(cr.get("missing_devices", []))
            if classification == "missing_drive":
                finding = f"missing {devs or '?'}"
            elif classification == "unrecognized_shape":
                finding = "instance shape not recognized by Aries script"
            else:
                finding = cr.get("raw_reason") or classification
            host_lines.append(
                f"{it['ip']} (serial {cr.get('host_serial') or '?'}, "
                f"shape {cr.get('shape') or '?'}): {finding}"
            )
        stdout = items[0]["classification_result"].get("stdout", "")
        classification = items[0]["classification_result"].get("classification", "generic_failure")
        issue_labels = {
            "missing_drive": "NVMe drive check failed — missing drive(s) detected.",
            "unrecognized_shape": "NVMe drive check failed — instance shape is not recognized by the Aries script.",
            "generic_failure": "NVMe drive check failed — Aries script returned an error.",
        }
        issue_text = stdout or issue_labels.get(
            classification, f"NVMe drive check failed — {classification}."
        )
        sr_drafts.append({
            "Date": datetime.now().strftime("%Y/%m/%d"),
            "Describe the Issue?": issue_text,
            "Impacted Service": SR_FIXED_IMPACTED_SERVICE,
            "Is this an urgent issue for you?": "(fill manually)",
            "Is the impact on going?": "(fill manually)",
            "Severity": SR_FIXED_SEVERITY,
            "Impacted Region": region_code,
            "Please Describe the business impact?": stdout or "\n".join(host_lines),
            "What tenancy is the issue related to?": tenancy,
            "OCIDs relating to this issue": ", ".join(ocids),
            "Comments": "",
            "_ips": [it["ip"] for it in items],
        })
    return sr_drafts


# ---- Lark SR form auto-fill (fill only — NEVER submits) -------------------
#
# Built from a real Playwright codegen capture against the live form
# (2026-09-17). Reuses the SAME persistent browser profile as every other
# page in this script (get_playwright_page) rather than a separate
# storage_state/auth.json — that file was only needed for codegen's own
# throwaway recording session, not for this integrated version. If you've
# ever logged into Lark once in this script's browser profile, it should
# already be authenticated here too.
#
# CONFIRMED from the capture and wired below: Date, Describe the Issue?,
# Impacted Service, Severity, Impacted Region, business-impact text.
#
# Tenancy and OCIDs are populated from instance_batch_list and filled using
# label-scoped selectors below. If Lark changes its generated markup, the form
# stays open and those specific fields are reported for manual completion.
#
# STILL MISSING (2026-09-17):
#   - Comments (blank by default)
#   - One more field, label unconfirmed, sits between "Is the impact
#     ongoing?" and "Severity" — the capture shows it filled with the
#     account username (edwinlim.rciw), but that may just be what was typed
#     during testing, not necessarily the intended value
#
# "Is this an urgent issue for you?" / "Is the impact ongoing?" are
# INTENTIONALLY never auto-filled — build_sr_groups() marks both
# "(fill manually)" by design (see FIELD_ORDER's is_dropdown notes in
# _build_sr_html), so this function skips them on purpose, not because
# they're unconfirmed.
LARK_SR_FORM_URL = "https://bytedance.us.larkoffice.com/share/base/form/shrusFAukoGlJ8JPKOjf5NhbTYb"


def fill_sr_form(page, draft: dict):
    """Fills the Lark SR Ticketing form from one build_sr_groups() draft
    dict. Never clicks Submit -- leaves the form sitting filled for manual
    review. `page` should already be on LARK_SR_FORM_URL (see
    get_playwright_page(LARK_SR_FORM_URL, ...))."""

    def _form_item(label: str):
        """Locate a Lark Base form item from its visible question label."""
        return page.get_by_text(label, exact=True).locator(
            "xpath=ancestor::div[contains(@class, 'bitable-form-item')][1]"
        )

    def _fill_text_by_label(label: str, value: str) -> bool:
        """Fill a text/rich-text control inside one labelled form item."""
        if not value:
            return False
        try:
            item = _form_item(label)
            for selector in ("textarea", "input", "[contenteditable='true']", ".adit-container"):
                controls = item.locator(selector)
                for idx in range(controls.count()):
                    control = controls.nth(idx)
                    if control.is_visible():
                        control.fill(str(value))
                        return True
        except Exception as exc:
            print(f"  Could not auto-fill '{label}': {exc}")
        return False

    def _select_by_label(label: str, value: str) -> bool:
        """Open a labelled single-select control and choose its exact value."""
        if not value:
            return False
        try:
            item = _form_item(label)
            trigger = item.locator(
                ".bitable-29d0ea__select-dropdown, [class*='select-dropdown']"
            ).first
            trigger.click()
            page.get_by_role("listitem").filter(
                has_text=re.compile(rf"^{re.escape(str(value))}$")
            ).click()
            return True
        except Exception as exc:
            print(f"  Could not auto-select '{label}' = '{value}': {exc}")
        return False

    # -- Date --
    page.locator(".bitable-29d0ea__date-time-editor").click()
    day = str(datetime.now().day)
    page.get_by_text(day, exact=True).click()

    # -- Describe the Issue? --
    page.locator(".adit-container").first.fill(draft["Describe the Issue?"])

    # -- Impacted Service --
    page.locator("div").filter(has_text=re.compile(r"^Please select$")).first.click()
    page.get_by_role("listitem").filter(has_text=draft["Impacted Service"]).click()

    # -- "Is this an urgent issue for you?" / "Is the impact on going?" --
    # Intentionally skipped: these are always "(fill manually)" in the
    # draft -- select them yourself before submitting.

    # -- Severity --
    page.locator(
        "div:nth-child(2) > .bitable-form-item__editor-container > "
        ".bitable-form_editor > .bitable-29d0ea__single-selector-editor > "
        ".bitable-29d0ea__select > .bitable-29d0ea__select-dropdown > .universe-icon"
    ).click()
    page.get_by_role("listitem").filter(has_text=draft["Severity"]).click()

    # -- Impacted Region -- (NOTE: this control has a "multiple" class in
    # its own markup even though exactly one region per SR draft is
    # correct here -- click the ONE matching option only, don't click
    # anything else afterward, or a second region chip can stick.)
    page.locator(
        ".bitable-29d0ea__select.multiple > .bitable-29d0ea__select-dropdown > .universe-icon > svg"
    ).first.click()
    page.get_by_role("listitem").filter(has_text=draft["Impacted Region"], exact=True).click()

    # -- Please Describe the business impact? --
    if not _fill_text_by_label(
        "Please Describe the business impact?",
        draft["Please Describe the business impact?"],
    ):
        print("  Could not auto-fill business impact; leave the tab open for manual entry.")

    # -- Tenancy + OCIDs (values come from instance_batch_list) ------------
    tenancy_value = draft.get("What tenancy is the issue related to?", "")
    ocid_value = draft.get("OCIDs relating to this issue", "")
    tenancy_filled = _select_by_label(
        "What tenancy is the issue related to?", tenancy_value
    )
    ocid_filled = _fill_text_by_label(
        "OCIDs relating to this issue", ocid_value
    )

    # -- Still intentionally/manual or not yet captured ---------------------
    # -- Comments (blank by default)
    # -- unidentified field between "ongoing?" and "Severity"
    still_manual = []
    if not tenancy_filled:
        still_manual.append(
            "What tenancy is the issue related to? (select: " + tenancy_value + ")"
        )
    if not ocid_filled:
        still_manual.append("OCIDs relating to this issue (paste: " + ocid_value + ")")
    still_manual.extend([
        "Comments (paste: " + draft.get("Comments", "") + ")",
        "Is this an urgent issue for you? (select manually)",
        "Is the impact on going? (select manually)",
        "Unidentified field between 'ongoing?' and 'Severity' — check the form",
    ])
    print("\n  Auto-filled: Date, Describe the Issue?, Impacted Service, Severity, "
          "Impacted Region, business impact"
          + (", Tenancy" if tenancy_filled else "")
          + (", OCIDs" if ocid_filled else "") + ".")
    print("  Still need to fill manually before submitting:")
    for item in still_manual:
        print(f"    - {item}")
    print("  NOT submitted — review everything, then click Submit yourself.\n")


def do_fill_sr_form_test():
    """[TEST] Fills the Lark SR form from the most recent SR draft(s)
    produced by do_disk_lost_aries_workflow() (option D), one at a time,
    pausing between each so you can review/submit before moving to the
    next. Never submits. If do_disk_lost_aries_workflow() hasn't been run
    yet this session, there's nothing to fill -- run option D first."""
    if not _last_sr_drafts:
        print("\nNo SR drafts in memory yet. Run option D (Maintenance precheck -> "
              "Aries NVMe check -> SR draft) first, then this option.")
        return
    page = get_playwright_page(LARK_SR_FORM_URL, prompt_label="Lark SR Ticketing form")
    for i, draft in enumerate(_last_sr_drafts, 1):
        print(f"\n=== Filling SR draft {i}/{len(_last_sr_drafts)} "
              f"({len(draft.get('_ips', []))} host(s): {draft.get('_ips', [])}) ===")
        fill_sr_form(page, draft)
        input(">>> Review the form (fill in the remaining manual fields above), "
              "then press ENTER to continue to the next draft (or Ctrl+C to stop here)... ")
        if i < len(_last_sr_drafts):
            page.goto(LARK_SR_FORM_URL, wait_until="domcontentloaded")


def _record_ip_values(record: dict) -> list:
    """Return every IPv4/IPv6 address exposed by an ie-oci record.

    Instance and maintenance records commonly include both `primaryIpv4` and
    `primaryIpv6`. Using `ipv6 or ipv4` indexes only one of them and makes an
    IPv4 Aries target impossible to match when IPv6 is also populated.
    """
    values = []
    for key in ("primaryIpv4", "primaryIpv6", "ipv4", "ipv6", "ip"):
        raw = record.get(key)
        items = raw if isinstance(raw, list) else [raw]
        for item in items:
            text = str(item or "").strip()
            if text and text not in values:
                values.append(text)
    return values


def build_sr_draft_for_completed_aries_host(
    ie_page, ip: str, classification_result: dict
):
    """Build one SR draft using a fresh instance lookup, without opening Lark."""
    inst_resp = instance_batch_list(ie_page, [ip])
    if "_error" in inst_resp:
        print(f"    SR data not generated for {ip}: instance lookup failed: {inst_resp.get('_error')}")
        return None

    instance_lookup = {}
    instance_records = inst_resp.get("data", []) or []
    for inst in instance_records:
        for inst_ip in _record_ip_values(inst):
            instance_lookup[inst_ip] = inst
        # Some ie-oci response versions nest addresses below another object.
        if ip not in instance_lookup and ip in json.dumps(inst, ensure_ascii=False):
            instance_lookup[ip] = inst
    if ip not in instance_lookup and len(instance_records) == 1:
        instance_lookup[ip] = instance_records[0]
    if ip not in instance_lookup:
        print(f"    WARNING: ie-oci returned no matching instance metadata for {ip}; SR fields will use UNKNOWN metadata.")
        instance_lookup[ip] = {
            "primaryIpv4": ip,
            "tenancy": "UNKNOWN",
            "region": "",
            "ocid": "UNKNOWN",
        }

    drafts = build_sr_groups(
        [{"ip": ip, "classification_result": classification_result}],
        instance_lookup,
    )
    if not drafts:
        print(f"    SR data not generated for {ip}: no matching instance/tenancy/region data.")
        return None
    return drafts[0]


def format_sr_draft_for_excel(draft: dict) -> str:
    """Render every SR field/value into one readable, wrapped Excel cell."""
    field_order = [
        "Date",
        "Describe the Issue?",
        "Impacted Service",
        "Is this an urgent issue for you?",
        "Is the impact on going?",
        "Severity",
        "Impacted Region",
        "Please Describe the business impact?",
        "What tenancy is the issue related to?",
        "OCIDs relating to this issue",
        "Comments",
    ]
    lines = []
    for field in field_order:
        value = str(draft.get(field, ""))
        # stdout is intentionally used in two fields; cap each individual field
        # so later fields (tenancy, OCIDs, comments) still fit in Excel's cell.
        lines.append(f"{field}:\n{value[:12000]}")
    # Excel cells have a hard 32,767-character limit.
    return "\n\n".join(lines)[:32000]



def _saved_row_text(row, *columns) -> str:
    """Return the first non-empty scalar text from a pandas row.

    `row.get(name)` returns a Series when an imported workbook contains
    duplicate column names. Never use Python `or` / `not` directly on that
    value, because pandas raises "truth value of a Series is ambiguous".
    """
    for column in columns:
        if column not in row.index:
            continue
        value = row.loc[column]
        candidates = value.tolist() if isinstance(value, pd.Series) else [value]
        for candidate in candidates:
            try:
                if pd.isna(candidate):
                    continue
            except (TypeError, ValueError):
                continue
            text = str(candidate).strip()
            if text:
                return text
    return ""



def do_show_saved_aries_sr_fields():
    """Option L: locate and print saved generated SR field data from Excel.

    Searches DiskAries_*.xlsx newest-first and accepts an exact IP/key or a
    unique substring of common identifiers (fault ticket id/link, deployment
    id, job id, or Aries run name). Does not open a browser or modify Lark.
    """
    key = input("Enter IP or saved Aries key: ").strip()
    if not key:
        print("No IP/key entered.")
        return

    all_files = sorted(
        Path.cwd().glob("DiskAries_*.xlsx"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    # Generated batch/final files accumulate quickly; searching the newest 100
    # bounds startup time while still covering a substantial recent history.
    files = all_files[:100]
    if len(all_files) > len(files):
        print(f"Searching the newest {len(files)} of {len(all_files)} Aries workbooks.")
    if not files:
        print("No DiskAries_*.xlsx result files found in this folder.")
        return

    key_lower = key.lower()
    exact_matches = []
    partial_matches = []
    match_columns = (
        "check_ip", "ip", "ipv4", "ipv6", "id", "link",
        "aries_deployment_id", "aries_job_id", "aries_change_run",
        "aries_change_run_link", "aries_change_name",
    )

    for file_path in files:
        try:
            data = pd.read_excel(file_path, sheet_name="ARIES Results")
        except Exception:
            try:
                data = pd.read_excel(file_path)
            except Exception as exc:
                print(f"Skipping unreadable workbook {file_path.name}: {exc}")
                continue

        for idx, row in data.iterrows():
            values = []
            for col in match_columns:
                value = _saved_row_text(row, col)
                if value:
                    values.append(value)
            lowered = [v.lower() for v in values if v]
            item = (file_path, idx, row)
            if key_lower in lowered:
                exact_matches.append(item)
            elif any(key_lower in value for value in lowered):
                partial_matches.append(item)

        # Prefer the newest workbook once it contains an exact match; FINAL and
        # batch workbooks may contain duplicate copies of the same host.
        if exact_matches:
            break

    matches = exact_matches or partial_matches
    if not matches:
        print(f"No saved Aries result matched: {key}")
        print("You may use an IP, fault-ticket ID, deployment ID, job ID, or run name.")
        return

    # De-duplicate repeated batch/final copies by IP + deployment id.
    unique = []
    seen = set()
    for item in matches:
        row = item[2]
        ip = _saved_row_text(row, "check_ip", "ip", "ipv4", "ipv6")
        dep = _saved_row_text(row, "aries_deployment_id")
        signature = (ip, dep)
        if signature not in seen:
            seen.add(signature)
            unique.append(item)

    if len(unique) > 1:
        print(f"Found {len(unique)} matches:")
        for number, (file_path, _, row) in enumerate(unique, 1):
            ip = _saved_row_text(row, "check_ip", "ip", "ipv4", "ipv6")
            dep = _saved_row_text(row, "aries_deployment_id")
            classification = _saved_row_text(row, "aries_classification")
            print(f"  {number}) {ip} | {classification} | {dep} | {file_path.name}")
        choice = input("Select match number: ").strip()
        try:
            selected = unique[int(choice) - 1]
        except (ValueError, IndexError):
            print("Invalid selection.")
            return
    else:
        selected = unique[0]

    file_path, _, row = selected
    ip = _saved_row_text(row, "check_ip", "ip", "ipv4", "ipv6")
    if not ip:
        print("The selected saved row has no check_ip/ip, so instance lookup cannot run.")
        return

    sr_fields = _saved_row_text(row, "generated_sr_fields")
    if not sr_fields:
        print(
            f"No generated_sr_fields data exists for {ip} in {file_path.name}.\n"
            "This workbook was created before SR fields were stored in Excel; "
            "rerun option D with the updated script."
        )
        return

    print(f"\nGenerated SR fields for {ip} ({file_path.name}):\n")
    print(sr_fields)
    print("\nThe same content is stored in the generated_sr_fields Excel column.")


def find_latest_disk_lost_export(folder: Path = None) -> Path:
    folder = folder or Path.cwd()
    candidates = list(folder.glob("disk_lost_tickets_*.xlsx"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def find_latest_nvme_timeout_reset_export(folder: Path = None) -> Path:
    folder = folder or Path.cwd()
    candidates = list(folder.glob("nvme_timeout_reset_tickets_*.xlsx"))
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)



def get_next_aries_change_number() -> int:
    """Return the next incrementing Aries change number used by the D workflow."""
    existing = []
    for pattern in ("DiskAries_*.xlsx", "disk_aries_*.xlsx"):
        for p in Path.cwd().glob(pattern):
            m = re.search(r"(?:check|change)[ _-]*(\d+)", p.stem, re.I)
            if m:
                existing.append(int(m.group(1)))
    return (max(existing) + 1) if existing else 1


def _normalise_disk_maintenance_state(value):
    value = str(value or "").strip()
    if not value:
        return ""
    return value.upper()


def classify_disk_maintenance_row(row):
    """
    Keep the row's existing columns intact while ensuring maintenance_state
    exists for the D workflow.
    """
    data = row.to_dict()
    if "maintenance_state" not in data:
        for key in ("maintenance", "maintenance_status", "state"):
            if key in data:
                data["maintenance_state"] = _normalise_disk_maintenance_state(data[key])
                break
        else:
            data["maintenance_state"] = ""
    else:
        data["maintenance_state"] = _normalise_disk_maintenance_state(
            data["maintenance_state"]
        )
    return data


def _aries_deployment_link(deployment_id: str, job_id: str = "", region: str = "i18n") -> str:
    """Build the human-visitable Aries link.

    With a job_id, return the per-job "tickets" deep link that opens directly
    on the response/error output for that host — this is the page that shows
    the script's stdout/stderr:
        {BASE}/modification/modificationList/tickets/{deployment_id}+{job_id}?creator={maintainer}
    Without a job_id, fall back to the deployment-level list page:
        {BASE}/modification/modificationList/{deployment_id}
    This URL pattern is CONFIRMED IDENTICAL across i18n and EUTTP (verified
    against a real EUTTP deployment-list URL, 2026-09-23) — only the base
    domain differs, which aries_region_base() resolves per region. Callers
    that don't have a region handy (e.g. the ticket-driven D-workflow's
    run_disk_aries_batch(), which doesn't thread region through yet) default
    to i18n and will build a wrong link for a EUTTP-region ticket — worth
    fixing when that flow is extended to EUTTP.
    """
    if not deployment_id:
        return ""
    base = aries_region_base(region)
    if job_id:
        return (f"{base}/modification/modificationList/tickets/"
                f"{deployment_id}+{job_id}?creator={ARIES_MAINTAINER}")
    return f"{base}/modification/modificationList/{deployment_id}"


def _extract_aries_job_id(payload) -> str:
    """Find the first Aries job id in a deploy response.

    Deploy responses may expose `jobID` directly or nest job objects under
    phases -> steps -> jobs. Restrict generic `id` matching to values that are
    descendants of a `jobs` collection so the deployment id is not mistaken
    for a job id.
    """
    if not isinstance(payload, (dict, list)):
        return ""
    if isinstance(payload, dict):
        direct = payload.get("jobID") or payload.get("jobId")
        if direct:
            return str(direct)
        jobs = payload.get("jobs")
        if isinstance(jobs, list):
            for job in jobs:
                if isinstance(job, str) and job:
                    return job
                if isinstance(job, dict):
                    value = job.get("jobID") or job.get("jobId") or job.get("id")
                    if value:
                        return str(value)
        for value in payload.values():
            found = _extract_aries_job_id(value)
            if found:
                return found
    else:
        for value in payload:
            found = _extract_aries_job_id(value)
            if found:
                return found
    return ""


def _row_aries_region(row) -> str:
    """Region to route an Aries call to, inferred from the ticket row's
    'region' column (set by do_ticketq()/export_tickets_from_web() as
    'I18N'/'EUTTP'). Falls back to i18n for older exports that predate that
    column, a blank/NaN value, or anything normalize_region() doesn't
    recognize — routing a ticket is not the place to raise/abort a batch
    over a missing region tag."""
    try:
        raw = row.get("region") if hasattr(row, "get") else None
    except Exception:
        raw = None
    try:
        region = normalize_region(raw)
    except Exception:
        return "i18n"
    return "i18n" if region == "both" else region


ARIES_RESUME_STATE_FILE = "aries_resume_state.json"
# Added 2026-09-29: entries older than this are dropped as stale rather than
# resumed forever — an abandoned/never-rerun deployment would otherwise sit
# in the state file indefinitely. 24h comfortably outlasts even the 660s
# NVMe-timeout-reset deploy timeout plus our poll window, while still
# refusing to resume something from days ago that the user may have already
# handled another way.
ARIES_RESUME_STATE_MAX_AGE_HOURS = 24


def _aries_resume_state_path() -> Path:
    return Path.cwd() / ARIES_RESUME_STATE_FILE


def _load_aries_resume_state() -> dict:
    path = _aries_resume_state_path()
    if not path.exists():
        return {}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"  Warning: could not read {path.name} ({exc}); starting with empty resume state.")
        return {}

    cutoff = datetime.now() - timedelta(hours=ARIES_RESUME_STATE_MAX_AGE_HOURS)
    fresh, stale = {}, []
    for key, entry in state.items():
        submitted_at = entry.get("submitted_at", "")
        try:
            when = datetime.fromisoformat(submitted_at)
        except (TypeError, ValueError):
            when = None  # missing/garbled timestamp — treat as stale, don't keep it forever
        if when is not None and when >= cutoff:
            fresh[key] = entry
        else:
            stale.append((key, submitted_at))

    if stale:
        print(f"  Dropping {len(stale)} resume-state entry(ies) older than "
              f"{ARIES_RESUME_STATE_MAX_AGE_HOURS}h (won't be auto-resumed):")
        for key, submitted_at in stale:
            print(f"    {key}  (submitted_at={submitted_at or '?'})")
        _save_aries_resume_state(fresh)

    return fresh


def _save_aries_resume_state(state: dict) -> None:
    """Atomic write (temp file + os.replace) so a crash mid-write can't
    corrupt the file we exist to survive crashes for."""
    path = _aries_resume_state_path()
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    except Exception as exc:
        print(f"  Warning: could not save resume state ({exc}). If this run is "
              f"interrupted, it will resubmit from scratch next time.")


def _aries_resume_key(source_label: str, ip: str) -> str:
    return f"{source_label}::{ip}"


def run_disk_aries_batch(batch: pd.DataFrame, aries_pages: dict, ie_page, aries_change_name: str,
                          deploy_timeout: int = 200, poll_timeout: int = None,
                          source_label: str = "") -> dict:
    """Run the real Aries NVMe-count check for every IP in this batch,
    ticket-by-ticket, using the Aries functions already defined in this file
    (aries_precheck -> aries_deploy -> aries_taskdetail -> classify_taskdetail_entry).

    This mirrors the proven inline logic from v3's do_maintenance_precheck_test()
    (renamed do_disk_lost_aries_workflow() as of this version — it submits real
    deployments, so the old "_test" name no longer matched this file's own
    convention that a "_test" function is read-only),
    but returns a per-IP result mapping so the batching / Excel layers can
    consume it (rather than only printing). `aries_pages` is a {region: page}
    dict of live, authenticated Aries pages from get_aries_page() — one per
    region actually present in the batch, passed in so each region's session
    is reused across all batches instead of re-authenticating. Region is read
    per-row (see _row_aries_region()) so a mixed I18N/EUTTP batch routes each
    ticket to its own region's Aries domain/unitID/version automatically; if
    a row's region has no matching open page yet (shouldn't normally happen,
    since the caller pre-opens one per distinct region in the batch), a
    session for it is opened here on the fly and cached into aries_pages for
    subsequent rows/batches.

    Submit-all-then-poll: every host in `batch` is submitted first, then all
    are polled together (each host's result is classified as it finishes), so
    a batch takes roughly one host's time rather than the sum of them all.
    `poll_timeout` (seconds, default ARIES_POLL_TIMEOUT_SECONDS) is the total
    poll window for the whole batch, counted from when the last host was
    submitted.

    Resume after interruption (2026-09-28): if `source_label` is given (the
    caller's ticket workbook filename — stable across a re-run after a
    crash, unlike aries_change_name which the user may retype differently),
    every deployment_id/job_id this call obtains is written to
    ARIES_RESUME_STATE_FILE in the current directory as soon as deploy
    succeeds — before polling, so a crash during polling still has it saved.
    On the NEXT call with the same source_label, any IP still recorded there
    (i.e. never reached a terminal result last time) is polled against its
    EXISTING deployment instead of being re-submitted, avoiding duplicate
    real Aries deployments for the same host. An IP's entry is removed once
    it reaches a terminal (classified) result; an IP that times out again
    stays recorded for the next resume. Passing "" (the default) disables
    this entirely — nothing is read or written, matching the old behavior.

    Returns: { ip: {
        "aries_change_run": <deployment name>,
        "aries_change_run_link": <deployment detail URL>,
        "aries_deployment_id": <id>,
        "aries_job_id": <job id>,
        "aries_status": <task status | error marker>,
        "aries_classification": <pass|missing_drive|agent_lost|...>,
        "aries_detail": <human-readable reason / missing devices / error>,
        "aries_missing_devices": <comma-joined /dev/nvme paths>,
    } }
    """
    results = {}
    ctxs = {}      # ip -> per-host context for every deployment we managed to submit
    pending = {}   # ip -> ctx, the subset still waiting on a terminal result
    poll_limit = poll_timeout or ARIES_POLL_TIMEOUT_SECONDS
    resume_state = _load_aries_resume_state() if source_label else {}

    # ---- Phase 1: submit every host in the batch (precheck -> deploy) ------
    # Submit-all-then-poll (2026-09-28): this used to submit ONE host, poll it
    # to completion, then move to the next — so N slow hosts took N x the
    # per-host wait (for the 660s NVMe-reset workflow, ~11 min each). All
    # deployments are now accepted first and polled together below, so the
    # whole batch takes roughly one host's time. Aries itself runs them
    # concurrently; nothing here changes what is submitted per host.
    for _, row in batch.iterrows():
        ip = str(row.get("check_ip") or row.get("ip") or "").strip()
        if not ip:
            continue

        region = _row_aries_region(row)
        aries_page = aries_pages.get(region)
        if aries_page is None:
            print(f"  [{ip}] No open Aries session for region {region!r} yet — opening one now.")
            aries_page = get_aries_page(region)
            aries_pages[region] = aries_page

        # Bug fixed 2026-09-18: this used to call _next_disk_check_name(),
        # a SEPARATE, hardcoded-base counter disconnected from the
        # aries_change_name the user typed. Each host still needs a distinct
        # name, so the per-host IP is appended as the disambiguator.
        name = f"{aries_change_name} - {ip}"
        rec = {
            "aries_change_run": name,
            "aries_change_run_link": "",
            "aries_deployment_id": "",
            "aries_job_id": "",
            "aries_status": "",
            "aries_classification": "",
            "aries_detail": "",
            "aries_host_serial": "",
            "aries_missing_devices": "",
            "aries_expected_count": "",
            "aries_actual_count": "",
            "aries_stdout": "",
            "aries_stderr": "",
            "generated_sr_fields": "",
        }

        resume_key = _aries_resume_key(source_label, ip) if source_label else None
        resumed = resume_state.get(resume_key) if resume_key else None
        if resumed:
            deployment_id = resumed.get("deployment_id")
            job_id = resumed.get("job_id", "")
            print(f"\n  [{ip}] Resuming previously submitted deployment "
                  f"{deployment_id} (from a run interrupted before it finished) "
                  f"— NOT re-submitting.")
            rec["aries_deployment_id"] = str(deployment_id or "")
            rec["aries_job_id"] = str(job_id or "")
            rec["aries_change_run_link"] = _aries_deployment_link(
                str(deployment_id) if deployment_id else "", str(job_id) if job_id else "", region,
            )
            ctx = {"rec": rec, "page": aries_page, "region": region,
                   "deployment_id": deployment_id, "job_id": job_id,
                   "entry": None, "last_task": None, "resume_key": resume_key}
            ctxs[ip] = ctx
            pending[ip] = ctx
            continue

        print(f"\n  [{ip}] Aries deployment name: {name} (region={region})")
        precheck_resp = aries_precheck(aries_page, name, ip, region, deploy_timeout)
        print(f"    Precheck response: {json.dumps(precheck_resp, ensure_ascii=False)[:300]}")
        if "_error" in precheck_resp:
            rec["aries_status"] = "precheck_error"
            rec["aries_detail"] = str(precheck_resp.get("_error", "precheck failed"))
            results[ip] = rec
            continue

        deploy_resp = aries_deploy(aries_page, name, ip, region, deploy_timeout)
        print(f"    Deploy response: {json.dumps(deploy_resp, ensure_ascii=False)[:500]}")
        if "_error" in deploy_resp:
            rec["aries_status"] = "deploy_error"
            rec["aries_detail"] = str(deploy_resp.get("_error", "Aries deploy failed"))
            results[ip] = rec
            print(f"    Deploy failed for {ip}; recording error and continuing.")
            continue
        deployment_id = (
            deploy_resp.get("id") or deploy_resp.get("deploymentID")
            or (deploy_resp.get("data") or {}).get("id")
        )
        job_id = _extract_aries_job_id(deploy_resp)

        rec["aries_deployment_id"] = str(deployment_id or "")
        rec["aries_job_id"] = str(job_id or "")
        rec["aries_change_run_link"] = _aries_deployment_link(
            str(deployment_id) if deployment_id else "",
            str(job_id) if job_id else "",
            region,
        )

        # Only deployment_id is required to poll — the taskdetail response
        # carries the jobID per host (the deploy response does NOT reliably
        # expose one).
        if not deployment_id:
            rec["aries_status"] = "deploy_incomplete"
            rec["aries_detail"] = "Could not determine deployment_id from deploy response."
            results[ip] = rec
            continue

        if resume_key:
            resume_state[resume_key] = {
                "deployment_id": deployment_id, "job_id": job_id or "", "region": region,
                "ip": ip, "submitted_at": datetime.now().isoformat(),
            }
            _save_aries_resume_state(resume_state)  # written NOW, before polling starts

        ctx = {"rec": rec, "page": aries_page, "region": region,
               "deployment_id": deployment_id, "job_id": job_id,
               "entry": None, "last_task": None, "resume_key": resume_key}
        ctxs[ip] = ctx
        pending[ip] = ctx

    # ---- Phase 2: poll every submitted deployment together -----------------
    finished = {}  # ip -> terminal taskdetail entry
    if pending:
        print(f"\n  Submitted {len(pending)} deployment(s); polling them together "
              f"(up to {poll_limit}s)...")
    deadline = time.time() + poll_limit
    next_progress_at = time.time() + 15
    while pending and time.time() < deadline:
        for ip in list(pending):
            ctx = pending[ip]
            # Unfiltered query (no status=...): returns this deployment's
            # entries whatever their status, so EUTTP status spellings that
            # differ from i18n's can't make the poll silently see nothing.
            task_resp = aries_taskdetail(ctx["page"], ctx["deployment_id"], ctx["job_id"],
                                         region=ctx["region"])
            ctx["last_task"] = task_resp
            if "_error" in task_resp:
                ctx["rec"]["aries_status"] = "poll_error"
                ctx["rec"]["aries_detail"] = str(task_resp.get("_error", "Aries taskdetail error"))
                print(f"    Polling failed for {ip}: {ctx['rec']['aries_detail']}")
                results[ip] = ctx["rec"]
                del pending[ip]
                continue
            data = task_resp.get("data") or []
            matching = [d for d in data if _same_ip(d.get("ip", ""), ip)]
            if not matching and len(data) == 1:
                matching = list(data)  # single-host deployment: the one entry is ours
            if matching:
                ctx["entry"] = matching[0]
                if _aries_status_terminal(matching[0].get("status", "")):
                    finished[ip] = matching[0]
                    del pending[ip]
                    print(f"    [{ip}] finished (status: {matching[0].get('status')}); "
                          f"{len(pending)} still running.")
        if not pending:
            break
        if time.time() >= next_progress_at:
            remaining = max(0, int(deadline - time.time()))
            waiting = ", ".join(
                f"{ip}={(c['entry'] or {}).get('status', 'no entry yet')}" for ip, c in pending.items()
            )
            print(f"    Still waiting on {len(pending)} host(s) ({remaining}s left): {waiting}")
            next_progress_at = time.time() + 15
        time.sleep(ARIES_POLL_INTERVAL_SECONDS)

    for ip, ctx in list(pending.items()):  # ran out of time
        rec = ctx["rec"]
        rec["aries_status"] = "no_task_data"
        diag = _aries_no_data_diagnostics(ctx["page"], str(ctx["deployment_id"]),
                                          ctx["region"], ctx["last_task"])
        rec["aries_detail"] = f"No terminal task data after {poll_limit}s | {diag}"
        print(f"    No terminal task data for {ip} after {poll_limit}s; {diag}")
        results[ip] = rec

    # ---- Phase 3: classify each finished host (+ SR template) --------------
    for ip, entry in finished.items():
        ctx = ctxs[ip]
        rec, aries_page, region = ctx["rec"], ctx["page"], ctx["region"]
        deployment_id, job_id = ctx["deployment_id"], ctx["job_id"]
        entry = _refetch_failed_entry(aries_page, deployment_id, entry, ip, region)

        # The taskdetail entry carries the authoritative deploymentID/jobID —
        # prefer them, and (re)build the per-job "tickets" deep link that opens
        # straight on this host's response/error output.
        entry_dep = entry.get("deploymentID") or deployment_id
        entry_job = entry.get("jobID") or job_id
        rec["aries_deployment_id"] = str(entry_dep or "")
        rec["aries_job_id"] = str(entry_job or "")
        rec["aries_change_run_link"] = _aries_deployment_link(
            str(entry_dep or ""), str(entry_job or ""), region
        )

        cr = classify_taskdetail_entry(entry)
        if cr.get("host_serial"):
            counts = (
                f"{cr.get('actual_count')}/{cr.get('expected_count')} NVMe present"
                if cr.get("expected_count") is not None else ""
            )
            print(
                f"    [{ip}] -> classification: {cr['classification']} "
                f"(serial={cr['host_serial']}, shape={cr.get('shape') or '?'}"
                + (f", {counts}" if counts else "") + ")"
            )
        else:
            print(f"    [{ip}] -> classification: {cr['classification']}")
        rec["aries_status"] = cr.get("status", "")
        rec["aries_classification"] = cr.get("classification", "")
        rec["aries_host_serial"] = cr.get("host_serial") or ""
        rec["aries_missing_devices"] = ", ".join(cr.get("missing_devices", []) or [])
        rec["aries_expected_count"] = (
            "" if cr.get("expected_count") is None else cr.get("expected_count")
        )
        rec["aries_actual_count"] = (
            "" if cr.get("actual_count") is None else cr.get("actual_count")
        )
        # Carry the raw check output so the Excel shows exactly what the Aries
        # script printed. Guard against Excel's 32,767-char per-cell limit.
        rec["aries_stdout"] = (entry.get("stdout") or "").strip()[:32000]
        rec["aries_stderr"] = (entry.get("stderr") or "").strip()[:32000]
        detail_bits = []
        if cr.get("raw_reason"):
            detail_bits.append(cr["raw_reason"])
        if cr.get("host_serial"):
            detail_bits.append(f"serial={cr['host_serial']}")
        if cr.get("shape"):
            detail_bits.append(f"shape={cr['shape']}")
        if cr.get("expected_count") is not None or cr.get("actual_count") is not None:
            detail_bits.append(
                f"expected={cr.get('expected_count')} actual={cr.get('actual_count')}"
            )
        if rec["aries_missing_devices"]:
            detail_bits.append(f"missing={rec['aries_missing_devices']}")
        if cr.get("classification") == "pass" and cr.get("pass_message"):
            detail_bits.append(cr["pass_message"])
        rec["aries_detail"] = " | ".join(str(b) for b in detail_bits if b)
        results[ip] = rec

        # For completed non-agent-lost faults, generate the complete SR field
        # set and store it in the Excel result. Do not open or manipulate Lark.
        if _aries_status_kind(cr.get("status")) == "failed" and cr.get("classification") != "agent_lost":
            sr_result = {**cr, "stdout": rec["aries_stdout"]}
            draft = build_sr_draft_for_completed_aries_host(ie_page, ip, sr_result)
            if draft:
                _last_sr_drafts.append(draft)
                rec["generated_sr_fields"] = format_sr_draft_for_excel(draft)
                print(f"    Generated SR field data for {ip}; it will be written to Excel.")
        elif cr.get("classification") == "agent_lost":
            print(f"    SR data skipped for {ip}: Aries agent lost.")

        if ctx.get("resume_key") and resume_state.pop(ctx["resume_key"], None) is not None:
            _save_aries_resume_state(resume_state)  # terminal result in hand — stop tracking it

    return results


def build_disk_aries_workbook(
    work: pd.DataFrame,
    results: dict,
    source_name: str,
    aries_change_name: str,
):
    """Build the final D workbook while retaining the usual ticket details."""
    out_df = work.copy()

    # Attach the result belonging to each IP.
    def result_for_row(row):
        ip = str(row.get("check_ip") or row.get("ip") or "").strip()
        result = results.get(ip, {}) if isinstance(results, dict) else {}
        if not isinstance(result, dict):
            result = {"aries_result": result}
        return result

    result_rows = [result_for_row(row) for _, row in out_df.iterrows()]
    result_df = pd.DataFrame(result_rows, index=out_df.index)

    for col in result_df.columns:
        if col in out_df.columns:
            out_df[f"aries_{col}"] = result_df[col]
        else:
            out_df[col] = result_df[col]

    out_df["aries_change_name"] = aries_change_name

    # Common link/id aliases used by the existing Aries runner.
    link_candidates = [
        "ticketUrl", "ticket_url", "ariesUrl", "aries_url",
        "changeUrl", "change_url", "url"
    ]
    link_col = next((c for c in link_candidates if c in out_df.columns), None)
    if link_col:
        out_df["ARIES Check / Change Link"] = out_df[link_col]

    id_candidates = ["ticketId", "ticket_id", "ariesTicketId", "change_id"]
    id_col = next((c for c in id_candidates if c in out_df.columns), None)
    if id_col:
        out_df["ARIES Check / Change ID"] = out_df[id_col]

    wb = Workbook()
    ws = wb.active
    ws.title = "ARIES Results"

    for col_idx, col in enumerate(out_df.columns, 1):
        cell = ws.cell(row=1, column=col_idx, value=str(col))
        cell.font = Font(bold=True)

    for row_idx, (_, row) in enumerate(out_df.iterrows(), 2):
        for col_idx, value in enumerate(row.tolist(), 1):
            ws.cell(row=row_idx, column=col_idx, value=value)

    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions

    # Give the raw-output columns room and wrap them so the stdout/stderr is
    # actually readable in the sheet.
    wide_cols = {"aries_stdout": 80, "aries_stderr": 60, "aries_detail": 45,
                 "aries_missing_devices": 30, "generated_sr_fields": 100}
    for col_idx, col in enumerate(out_df.columns, 1):
        name = str(col)
        if name in wide_cols:
            ws.column_dimensions[get_column_letter(col_idx)].width = wide_cols[name]
            for row_idx in range(2, ws.max_row + 1):
                ws.cell(row=row_idx, column=col_idx).alignment = Alignment(
                    wrap_text=True, vertical="top"
                )

    # Make detected Aries links clickable.
    for col_idx, col in enumerate(out_df.columns, 1):
        if "link" in str(col).lower() or "url" in str(col).lower():
            for row_idx in range(2, ws.max_row + 1):
                value = ws.cell(row=row_idx, column=col_idx).value
                if isinstance(value, str) and value.startswith(("http://", "https://")):
                    ws.cell(row=row_idx, column=col_idx).hyperlink = value
                    ws.cell(row=row_idx, column=col_idx).style = "Hyperlink"

    summary = wb.create_sheet("Summary")
    summary["A1"] = "Disk Aries Results"
    summary["A1"].font = Font(bold=True, size=14)
    summary["A2"] = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    summary["A3"] = f"Source: {source_name}"
    summary["A4"] = f"Aries change/run name: {aries_change_name}"
    summary["A5"] = f"Tickets requiring Aries: {len(out_df)}"
    summary.column_dimensions["A"].width = 70

    return wb

def do_disk_lost_aries_workflow():
    """
    Disk-lost workflow. NOT read-only — this submits real Aries deployments
    (precheck + deploy) that create real, PSM-gated change requests against
    real hosts. Renamed from do_maintenance_precheck_test() (2026-09-18) so
    the name stops implying it's a side-effect-free test, matching this
    file's convention that a "_test"/debug function never submits anything.

    Scheduled tickets are exported/opened separately. Non-scheduled tickets are
    reviewed once (see the confirmation prompt before the first batch below),
    then processed through Aries in configurable batches (ARIES_BATCH_SIZE).

    After each batch:
      - the current batch completes its full Aries workflow first
      - an Excel result is written/opened
      - the user is asked whether to continue
      - typing ALL processes the remaining tickets without further prompts
      - pressing ENTER processes the next batch
    """
    path = find_latest_disk_lost_export()
    if path is None:
        print("No disk_lost_tickets_*.xlsx found.")
        return

    print("\n========================================")
    print(f"  Disk Lost Excel : {path.name}")
    print("========================================\n")

    df = pd.read_excel(path)
    if df.empty:
        print("No rows found.")
        return

    # Ask for the Aries change name once, at the point the D workflow starts.
    # Blank input preserves the existing incrementing/default behavior.
    default_change_name = f"Disk: Lost check {get_next_aries_change_number()}"
    change_name_input = input(
        f"Aries change name [{default_change_name}]: "
    ).strip()
    aries_change_name = change_name_input or default_change_name

    # Existing maintenance classification.
    classified_rows = []
    for _, row in df.iterrows():
        classified_rows.append(classify_disk_maintenance_row(row))

    work = pd.DataFrame(classified_rows)

    # ---- Live maintenance-state lookup (ported from v3) --------------------
    # The disk_lost_tickets_*.xlsx written by do_ticketq() does NOT carry a
    # live maintenance_state — so relying on a workbook column here would
    # almost always classify everything as "needs Aries" and silently skip
    # the "if SCHEDULED -> Recreate" branch. Fetch the real state per IP from
    # ie-oci /api/maintenance/batch_list, exactly as v3 did, and overwrite the
    # maintenance_state column with it. Falls back to whatever the workbook
    # had (via classify_disk_maintenance_row) if the lookup fails.
    def _row_ip(row):
        return str(row.get("check_ip") or row.get("ip") or "").strip()

    lookup_ips = list(dict.fromkeys(
        _row_ip(row) for _, row in work.iterrows() if _row_ip(row)
    ))
    if lookup_ips:
        print(f"\nLooking up live maintenance state for {len(lookup_ips)} IP(s)...")
        ie_page = get_playwright_page(
            MAINTENANCE_LOOKUP_PAGE, prompt_label="ie-oci instance batch-query page"
        )
        maint_resp = maintenance_batch_list(ie_page, lookup_ips)
        if "_error" in maint_resp:
            print(f"  Maintenance lookup failed ({maint_resp.get('_error')}); "
                  f"falling back to the workbook's maintenance_state column.")
        else:
            maint_by_ip = {}
            for event in maint_resp.get("data", []) or []:
                for event_ip in _record_ip_values(event):
                    maint_by_ip.setdefault(event_ip, []).append(event)

            def _live_state(row):
                ip = _row_ip(row)
                pick = pick_latest_maintenance_state(maint_by_ip.get(ip, []))
                state = pick.get("lifecycleState")
                # No event on record -> keep whatever the workbook had (may be
                # empty), rather than clobbering it to "".
                if state is None:
                    return row.get("maintenance_state", "")
                return _normalise_disk_maintenance_state(state)

            work["maintenance_state"] = work.apply(_live_state, axis=1)
            live_counts = work["maintenance_state"].replace("", "none on record").value_counts()
            print("  Live maintenance states: "
                  + ", ".join(f"{k}={v}" for k, v in live_counts.items()))

    scheduled_mask = (
        work["maintenance_state"].astype(str).str.strip().str.upper() == "SCHEDULED"
    ) if "maintenance_state" in work.columns else pd.Series(False, index=work.index)

    scheduled = work.loc[scheduled_mask].copy()
    aries_work = work.loc[~scheduled_mask].copy().reset_index(drop=True)

    # 1) Always export/open the scheduled tickets separately.
    if not scheduled.empty:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        scheduled_out = path.parent / f"DiskScheduled_{ts}.xlsx"
        scheduled.to_excel(scheduled_out, index=False)
        print(f"\nScheduled tickets: {len(scheduled)}")
        print(f"Saved: {scheduled_out}")
        open_file(scheduled_out)
    else:
        print("\nNo SCHEDULED tickets found.")

    if aries_work.empty:
        print("\nNo tickets require Aries.")
        return

    print(f"\nTickets requiring Aries: {len(aries_work)}")
    print(f"Aries change name: {aries_change_name}")
    print(f"Batch size: {ARIES_BATCH_SIZE}")

    # Pre-submission review — this is the ONE thing standing between "a
    # ticket matched a keyword" and "a real Aries deployment (precheck +
    # deploy) gets submitted against a real host." Aries' own PSM-approval
    # step still gates actual execution on the host, but submission itself
    # creates a real, attributed change request, so show what's about to be
    # submitted and require an explicit go-ahead before the FIRST batch —
    # the existing "press ENTER for next batch / ALL" prompt only protects
    # batch 2 onward, so without this, batch 1 fired unconditionally.
    print(f"\nAbout to submit Aries precheck+deploy for these {len(aries_work)} host(s):")
    for _, row in aries_work.iterrows():
        preview_ip = row.get("check_ip") or row.get("ip") or "?"
        preview_id = row.get("id", "?")
        print(f"    ticket {preview_id}  ->  {preview_ip}")
    confirm = input(
        f"\nSubmit real Aries deployments for {len(aries_work)} host(s)? [y/N]: "
    ).strip().lower()
    if confirm != "y":
        print("Aborted — nothing was submitted.")
        return

    # Authenticate one Aries session per distinct region actually present in
    # this batch (usually just one, but a mixed export from option E's
    # "Both" can carry I18N and EUTTP tickets together) and reuse each across
    # every batch below, so we don't re-prompt for login mid-run. Falls back
    # to i18n alone for older exports with no 'region' column.
    regions_present = sorted({_row_aries_region(row) for _, row in aries_work.iterrows()})
    print(f"\nRegion(s) in this run: {', '.join(r.upper() for r in regions_present)}")
    aries_pages = {region: get_aries_page(region) for region in regions_present}

    # Process in batches. This is intentionally driven by ARIES_BATCH_SIZE so it
    # can later be changed to 10 (or another number) in one place.
    all_results = {}
    run_all = False
    offset = 0

    while offset < len(aries_work):
        batch_end = min(offset + ARIES_BATCH_SIZE, len(aries_work))
        batch = aries_work.iloc[offset:batch_end].copy()

        print("\n" + "=" * 60)
        print(
            f"  Aries batch {offset + 1}-{batch_end} of {len(aries_work)}"
        )
        print("=" * 60)

        batch_results = run_disk_aries_batch(
            batch,
            aries_pages,
            ie_page,
            aries_change_name=aries_change_name,
            source_label=path.name,
        )

        if batch_results:
            all_results.update(batch_results)

        # Write/open the result for the batch before asking whether to continue.
        batch_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        batch_out = path.parent / f"DiskAries_{batch_ts}_batch_{offset + 1}-{batch_end}.xlsx"
        batch_wb = build_disk_aries_workbook(
            aries_work,
            all_results,
            path.name,
            aries_change_name=aries_change_name,
        )
        batch_wb.save(batch_out)

        print(f"\nSaved current Aries results: {batch_out}")
        open_file(batch_out)

        offset = batch_end

        if offset >= len(aries_work):
            break

        if run_all:
            continue

        answer = input(
            f"\nBatch {offset // ARIES_BATCH_SIZE} complete. "
            f"Press ENTER for the next {ARIES_BATCH_SIZE}, or type ALL "
            f"to run the remaining {len(aries_work) - offset} ticket(s): "
        ).strip().upper()

        if answer == "ALL":
            run_all = True

    # Final consolidated workbook after every Aries ticket has completed.
    final_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    final_out = path.parent / f"DiskAries_{final_ts}_FINAL.xlsx"
    final_wb = build_disk_aries_workbook(
        aries_work,
        all_results,
        path.name,
        aries_change_name=aries_change_name,
    )
    final_wb.save(final_out)

    print("\n" + "=" * 60)
    print("  ALL ARIES TICKETS COMPLETE")
    print("=" * 60)
    print(f"Saved final Aries workbook: {final_out}")
    open_file(final_out)
    print("Done.")


def do_nvme_timeout_reset_workflow():
    """
    NVMe QID-timeout/reset-controller workflow (see
    NVME_TIMEOUT_RESET_DETAIL_KEYWORDS for the confirmed process). NOT
    read-only — submits real Aries deployments, and on completion submits
    real Reinstall/Recreate requests too.

    Runs the same "check NVMEs" Aries script as the D (disk-lost) workflow
    via run_disk_aries_batch() — including its existing per-host SR-draft
    generation (build_sr_draft_for_completed_aries_host()) for any
    non-agent_lost failure — but with the deploy-side timeout raised to
    ARIES_NVME_TIMEOUT_RESET_DEPLOY_TIMEOUT_SECONDS (660s) instead of the
    usual 200s. Once every ticket's Aries result is in, routes by outcome:
      - agent_lost    -> Recreate (submitted here)
      - other failure -> OCI SR (already generated per-host by
                          run_disk_aries_batch(); nothing further submitted)
      - pass          -> Reinstall (submitted here)
    "Verify fault" after Reinstall means closing the fault ticket on the
    fault platform, which is intentionally MANUAL (no ticket-retrieval/close
    workflow exists here, and closing by hand is preferred): this submits the
    Reinstall, then lists the fault ticket ids to close and marks them in the
    output workbook. Nothing auto-recreates a host after a Reinstall.
    """
    path = find_latest_nvme_timeout_reset_export()
    if path is None:
        print("No nvme_timeout_reset_tickets_*.xlsx found. Run option 1 or 6 first.")
        return

    print("\n========================================")
    print(f"  NVMe Timeout/Reset Excel : {path.name}")
    print("========================================\n")

    aries_work = pd.read_excel(path)
    if aries_work.empty:
        print("No rows found.")
        return
    aries_work = aries_work.reset_index(drop=True)

    default_change_name = f"NVMe Timeout Reset check {get_next_aries_change_number()}"
    change_name_input = input(f"Aries change name [{default_change_name}]: ").strip()
    aries_change_name = change_name_input or default_change_name

    ie_page = get_playwright_page(
        MAINTENANCE_LOOKUP_PAGE, prompt_label="ie-oci instance batch-query page"
    )

    print(f"\nTickets requiring Aries: {len(aries_work)}")
    print(f"Aries change name: {aries_change_name}")
    print(f"Deploy timeout: {ARIES_NVME_TIMEOUT_RESET_DEPLOY_TIMEOUT_SECONDS}s (vs. the usual 200s); "
          f"polling up to {ARIES_NVME_TIMEOUT_RESET_DEPLOY_TIMEOUT_SECONDS + 60}s per host")
    print(f"Batch size: {ARIES_BATCH_SIZE}")

    print(f"\nAbout to submit Aries precheck+deploy for these {len(aries_work)} host(s):")
    for _, row in aries_work.iterrows():
        preview_ip = row.get("check_ip") or row.get("ip") or "?"
        preview_id = row.get("id", "?")
        print(f"    ticket {preview_id}  ->  {preview_ip}")
    confirm = input(
        f"\nSubmit real Aries deployments for {len(aries_work)} host(s)? [y/N]: "
    ).strip().lower()
    if confirm != "y":
        print("Aborted — nothing was submitted.")
        return

    try:
        regions_present = sorted({_row_aries_region(row) for _, row in aries_work.iterrows()})
    except ValueError as exc:
        print(f"\nAborted before Aries submission: {exc}")
        print("Ensure the source ticket workbook contains a valid region column (I18N/EUTTP).")
        return
    print(f"\nRegion(s) in this run: {', '.join(r.upper() for r in regions_present)}")
    aries_pages = {region: get_aries_page(region) for region in regions_present}

    all_results = {}
    run_all = False
    offset = 0

    while offset < len(aries_work):
        batch_end = min(offset + ARIES_BATCH_SIZE, len(aries_work))
        batch = aries_work.iloc[offset:batch_end].copy()

        print("\n" + "=" * 60)
        print(f"  Aries batch {offset + 1}-{batch_end} of {len(aries_work)}")
        print("=" * 60)

        batch_results = run_disk_aries_batch(
            batch,
            aries_pages,
            ie_page,
            aries_change_name=aries_change_name,
            deploy_timeout=ARIES_NVME_TIMEOUT_RESET_DEPLOY_TIMEOUT_SECONDS,
            # Our poll must outlast Aries' own per-host timeout, or a slow
            # (but still running) check is wrongly recorded as no_task_data.
            poll_timeout=ARIES_NVME_TIMEOUT_RESET_DEPLOY_TIMEOUT_SECONDS + 60,
            source_label=path.name,
        )
        if batch_results:
            all_results.update(batch_results)

        batch_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        batch_out = path.parent / f"NvmeTimeoutReset_{batch_ts}_batch_{offset + 1}-{batch_end}.xlsx"
        batch_wb = build_disk_aries_workbook(
            aries_work, all_results, path.name, aries_change_name=aries_change_name,
        )
        batch_wb.save(batch_out)
        print(f"\nSaved current Aries results: {batch_out}")
        open_file(batch_out)

        offset = batch_end
        if offset >= len(aries_work):
            break
        if run_all:
            continue
        answer = input(
            f"\nBatch {offset // ARIES_BATCH_SIZE} complete. "
            f"Press ENTER for the next {ARIES_BATCH_SIZE}, or type ALL "
            f"to run the remaining {len(aries_work) - offset} ticket(s): "
        ).strip().upper()
        if answer == "ALL":
            run_all = True

    # ---- Outcome routing ---------------------------------------------------
    # Any non-agent_lost failure already got a per-host SR draft written into
    # all_results[ip]["generated_sr_fields"] by run_disk_aries_batch() itself
    # (same build_sr_draft_for_completed_aries_host() call the D workflow
    # uses) — nothing further to submit for those, they're just tallied here.
    recreate_ips, reinstall_ips, sr_only_ips, unresolved_ips = [], [], [], []
    for ip, rec in all_results.items():
        classification = rec.get("aries_classification", "")
        if classification == "agent_lost":
            recreate_ips.append(ip)
        elif classification == "pass":
            reinstall_ips.append(ip)
        elif rec.get("generated_sr_fields"):
            sr_only_ips.append(ip)
        else:
            unresolved_ips.append(ip)

    print("\n" + "=" * 60)
    print("  OUTCOME ROUTING")
    print("=" * 60)
    print(f"  agent_lost -> Recreate : {len(recreate_ips)}")
    print(f"  pass       -> Reinstall: {len(reinstall_ips)}")
    print(f"  other fail -> OCI SR   : {len(sr_only_ips)} (SR field data already written to the Excel above)")
    if unresolved_ips:
        print(f"  UNRESOLVED (precheck/deploy/poll error — check manually): {len(unresolved_ips)}")
        for ip in unresolved_ips:
            print(f"    {ip}: {all_results[ip].get('aries_status', '?')} — {all_results[ip].get('aries_detail', '')}")

    recreate_results = {}
    if recreate_ips:
        print(f"\nSubmitting Recreate for {len(recreate_ips)} agent_lost host(s)...")
        recreate_results = run_recreates(recreate_ips)

    reinstall_results = {}
    if reinstall_ips:
        print(f"\nSubmitting Reinstall for {len(reinstall_ips)} passing host(s)...")
        reinstall_results = run_reinstalls(reinstall_ips)
        # "Verify fault" = close the fault ticket on the fault platform, done
        # by hand (see NVME_TIMEOUT_RESET_DETAIL_KEYWORDS notes).
        ticket_by_ip, link_by_ip = {}, {}
        for _, wrow in aries_work.iterrows():
            wip = str(wrow.get("check_ip") or wrow.get("ip") or "").strip()
            if wip:
                ticket_by_ip[wip] = wrow.get("id", "?")
                wlink = wrow.get("link", "")
                link_by_ip[wip] = "" if pd.isna(wlink) else str(wlink)
        print("\n  Reinstall submitted. Close these fault tickets manually on the fault")
        print("  platform once you're satisfied the fault is cleared:")
        for ip in reinstall_ips:
            print(f"    ticket {ticket_by_ip.get(ip, '?')}  ->  {ip}")
            if link_by_ip.get(ip):
                print(f"      {link_by_ip[ip]}")

    for ip, res in recreate_results.items():
        rec = all_results.setdefault(ip, {})
        rec["recreate_status"] = res.get("status", "")
        rec["recreate_ticketId"] = res.get("ticketId", "")
        rec["recreate_ticketUrl"] = res.get("ticketUrl", "")
    for ip, res in reinstall_results.items():
        rec = all_results.setdefault(ip, {})
        rec["reinstall_status"] = res.get("status", "")
        rec["reinstall_ticketId"] = res.get("ticketId", "")
        rec["reinstall_ticketUrl"] = res.get("ticketUrl", "")
        rec["fault_verification"] = "Close fault ticket manually on the fault platform"

    final_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    final_out = path.parent / f"NvmeTimeoutReset_{final_ts}_FINAL.xlsx"
    final_wb = build_disk_aries_workbook(
        aries_work, all_results, path.name, aries_change_name=aries_change_name,
    )
    final_wb.save(final_out)

    print("\n" + "=" * 60)
    print("  ALL NVMe TIMEOUT/RESET TICKETS COMPLETE")
    print("=" * 60)
    print(f"Saved final workbook: {final_out}")
    open_file(final_out)
    print("Done.")

def _parse_ip_list_multiline(prompt_label: str = "IP(s)") -> list:
    """Same multi-line/comma-separated IP entry pattern used by
    do_reboot_manual() etc., factored out for reuse by the standalone
    Aries check shortcuts."""
    print()
    print(f"Enter {prompt_label} to check.")
    print("  - Separate multiple IPs with commas")
    print("  - Or paste several lines, then press ENTER on an empty line")
    print()
    lines = []
    while True:
        try:
            line = input("IP(s): " if not lines else "").strip()
        except EOFError:
            break
        if not line:
            break
        lines.append(line)
    raw = " ".join(lines).replace("\n", ",").replace(" ", ",")
    return [ip.strip() for ip in raw.split(",") if ip.strip()]


def build_aries_manual_workbook(results: dict, mode_label: str) -> Workbook:
    """Small styled workbook for the standalone Aries check shortcuts
    (option A/B below) — one row per IP checked, whatever fields that
    check's rec dict carries (disk check and NIC check have different
    columns, so this stays column-agnostic rather than hardcoding either
    shape)."""
    rows = []
    for ip, rec in results.items():
        row = {"ip": ip}
        row.update(rec if isinstance(rec, dict) else {"result": rec})
        rows.append(row)
    out_df = pd.DataFrame(rows)
    wb = Workbook()
    ws = wb.active
    ws.title = f"{mode_label} Results"[:31]
    for c, name in enumerate(out_df.columns, 1):
        cell = ws.cell(1, c, str(name))
        cell.font = Font(bold=True)
        cell.alignment = Alignment(wrap_text=True)
    for r, row in enumerate(out_df.itertuples(index=False), 2):
        for c, value in enumerate(row, 1):
            ws.cell(r, c, value=value).alignment = Alignment(wrap_text=True, vertical="top")
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    wide = {"aries_stdout": 80, "aries_stderr": 60, "aries_detail": 45,
            "generated_sr_fields": 90, "aries_change_run": 34, "ip": 30,
            "aries_change_run_link": 40}
    for c, name in enumerate(out_df.columns, 1):
        ws.column_dimensions[get_column_letter(c)].width = wide.get(str(name), 18)
    for c, name in enumerate(out_df.columns, 1):
        if "link" in str(name).lower():
            for r in range(2, ws.max_row + 1):
                v = ws.cell(r, c).value
                if isinstance(v, str) and v.startswith(("http://", "https://")):
                    ws.cell(r, c).hyperlink = v
                    ws.cell(r, c).style = "Hyperlink"
    return wb


def prompt_aries_region() -> str:
    print("\nSelect Aries region:")
    print("  1) I18N")
    print("  2) EUTTP")
    choice = input("Region [1]: ").strip() or "1"
    return {"1": "i18n", "2": "euttp"}.get(choice, "i18n")


def do_aries_disk_check_manual():
    """Standalone shortcut: given IP(s), run the NVMe disk check directly
    through Aries — no ticket/Excel filtering, no reinstall/recreate
    branching, just precheck -> deploy -> poll -> classify per IP, printed
    live and logged to a small workbook. Uses the same run_aries_disk_check()
    helper the full "D" ticket-driven workflow uses under the hood, so the
    classification logic (missing_drive / unrecognized_shape / agent_lost /
    pass, with host_serial/shape/counts) is identical either way."""
    ips = _parse_ip_list_multiline("IP(s) to disk-check")
    if not ips:
        print("No IPs entered.")
        return

    region = prompt_aries_region()

    change_name = input(
        f"Aries change name [default: \"Manual Disk Check {datetime.now().strftime('%Y-%m-%d %H:%M')}\"]: "
    ).strip() or f"Manual Disk Check {datetime.now().strftime('%Y-%m-%d %H:%M')}"

    aries_page = get_aries_page(region)
    ie_page = None  # opened lazily, only if a host fails and needs an SR template
    results = {}
    for ip in ips:
        print(f"\n[{ip}] Running Aries NVMe check...")
        rec = run_aries_disk_check(ip, aries_page, change_name, region=region)
        results[ip] = rec
        cr_bits = [rec.get("aries_classification", "?")]
        if rec.get("aries_host_serial"):
            cr_bits.append(f"serial={rec['aries_host_serial']}")
        if rec.get("aries_expected_count") != "" or rec.get("aries_actual_count") != "":
            cr_bits.append(f"{rec.get('aries_actual_count')}/{rec.get('aries_expected_count')} NVMe")
        print(f"  -> {' | '.join(str(b) for b in cr_bits if b)}")
        if rec.get("aries_detail"):
            print(f"     {rec['aries_detail']}")

        # Same SR-template output as the D workflow: any completed, failed,
        # non-agent_lost host gets the full SR field set generated from the
        # ie-oci instance lookup (tenancy / region / OCID) — written to the
        # workbook's generated_sr_fields column, echoed here, and queued for
        # menu option S. Never touches Lark. Region-agnostic (works for
        # I18N and EUTTP hosts alike; region comes from the instance record).
        if (_aries_status_kind(rec.get("aries_status")) == "failed"
                and rec.get("aries_classification") not in ("agent_lost", "pass", "")):
            if ie_page is None:
                ie_page = get_playwright_page(
                    MAINTENANCE_LOOKUP_PAGE,
                    prompt_label="ie-oci instance batch-query page (needed for the SR template)",
                )
            sr_result = {
                "classification": rec.get("aries_classification"),
                "status": rec.get("aries_status"),
                "host_serial": rec.get("aries_host_serial"),
                "shape": rec.get("aries_shape"),
                "missing_devices": [d.strip() for d in str(rec.get("aries_missing_devices", "")).split(",") if d.strip()],
                "raw_reason": rec.get("_raw_reason", ""),
                "stdout": rec.get("aries_stdout", ""),
            }
            draft = build_sr_draft_for_completed_aries_host(ie_page, ip, sr_result)
            if draft:
                _last_sr_drafts.append(draft)
                rec["generated_sr_fields"] = format_sr_draft_for_excel(draft)
                print("\n     ---- SR template ----")
                for line in rec["generated_sr_fields"].splitlines():
                    print(f"     {line}")
                print("     ---------------------")
        rec.pop("_raw_reason", None)

    out = Path.cwd() / f"aries_disk_check_manual_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    build_aries_manual_workbook(results, "Disk Check").save(out)
    print(f"\nSaved: {out}")
    open_file(out)


def do_aries_nic_check_manual():
    """Standalone shortcut: given IP(s), run the NIC-state check directly
    through Aries (the OS EIPv4/EIPv6 side) — no ticket/Excel filtering, no
    reinstall/recreate branching, just precheck -> deploy -> poll ->
    classify per IP, printed live and logged to a small workbook. Uses the
    same run_aries_nic_check() helper the full dual-IP workflow uses under
    the hood, so the classification (pass / no_carrier / agent_lost /
    unknown) is identical either way."""
    ips = _parse_ip_list_multiline("IP(s) to NIC-check")
    if not ips:
        print("No IPs entered.")
        return

    region = prompt_aries_region()

    change_name = input(
        f"Aries change name [default: \"Manual NIC Check {datetime.now().strftime('%Y-%m-%d %H:%M')}\"]: "
    ).strip() or f"Manual NIC Check {datetime.now().strftime('%Y-%m-%d %H:%M')}"

    aries_page = get_aries_page(region)
    results = {}
    for ip in ips:
        print(f"\n[{ip}] Running Aries NIC-state check...")
        rec = run_aries_nic_check(ip, aries_page, change_name, region=region)
        results[ip] = rec
        print(f"  -> {rec.get('aries_nic_classification', '?')}"
              + (f" | {rec['aries_nic_detail']}" if rec.get("aries_nic_detail") else ""))

    out = Path.cwd() / f"aries_nic_check_manual_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    build_aries_manual_workbook(results, "NIC Check").save(out)
    print(f"\nSaved: {out}")
    open_file(out)


# ---------------------------------------------------------------------------
# SSH access to hosts (runbook: kinit -> jump-proxy -> root@host).
# Verified by hand 2026-10-02 as:
#   ssh -o BatchMode=yes -J <user>@jump-proxy-sg.tiktok-row.org root@<ip> hostname
# The explicit <user>@ on the jump host matters: without it ssh uses the local Mac
# username and the proxy rejects it ("Permission denied (gssapi-with-mic)").
# ---------------------------------------------------------------------------
SSH_JUMP_PROXY = {
    "i18n": "jump-proxy-sg.tiktok-row.org",
    "euttp": "jump-proxy-ie.tiktok-eu.org",
}
KERBEROS_REALM = "BYTEDANCE.COM"
SSH_PERMISSION_HELP = {
    "i18n": [
        "Orthrus (I18N/NON-TT): https://orthrus-i18n.tiktok-row.org/v2/permission/server",
        "Orthrus (I18N-TT):     https://orthrus-nontt.byted.org/v2/permission/server",
        "XFlow ROW/TT:          https://xflow-i18n.tiktok-row.net/workflow/new/Operator_add",
        "XFlow ROW/NON-TT:      https://xflow.sinf.net/workflow/new/Operator_add",
    ],
    "euttp": [
        "Orthrus (EU-TTP): https://orthrus-eu.tiktok-eu.org/v2/permission/server",
        "XFlow EU-TTP:     https://xflow-ttp-eu.tiktok-row.net/workflow/new/Operator_add",
    ],
}
_SSH_USER_CACHE = ""


def _kerberos_user() -> str:
    """Username from the current Kerberos cache (`klist`), or ''. Handles both the
    MIT ("Default principal:") and macOS ("Principal:") output formats."""
    try:
        out = subprocess.run(["klist"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    m = re.search(r"(?:Default principal|Principal):\s*([^@\s]+)@", out)
    return m.group(1) if m else ""


def _ssh_user() -> str:
    global _SSH_USER_CACHE
    if not _SSH_USER_CACHE:
        user = os.environ.get("TICKET_TOOLS_SSH_USER", "").strip() or _kerberos_user()
        if not user:
            user = input("Kerberos/SSH username (e.g. firstname.lastname): ").strip()
        _SSH_USER_CACHE = user
    return _SSH_USER_CACHE


def classify_ssh_failure(stderr: str, user: str, proxy: str) -> str:
    """Best-effort bucket for an ssh failure. 'jump_auth' = rejected at the jump
    proxy (expired ticket / wrong username); 'host_permission' = rejected by the
    target host; both are inferred from ssh's message, not confirmed."""
    s = (stderr or "").lower()
    if "host key verification failed" in s or "remote host identification has changed" in s:
        return "host_key"
    if "permission denied" in s:
        return "jump_auth" if f"{user}@{proxy}".lower() in s else "host_permission"
    if any(k in s for k in ("timed out", "no route to host", "connection refused",
                            "connection closed", "could not resolve")):
        return "unreachable"
    return "other"


def ssh_run(ip: str, command: str, region: str = "i18n", timeout: int = 60,
            retry_kinit: bool = True) -> dict:
    """Run one command as root on `ip` via the region's jump proxy, non-interactively.
    Returns {ok, category, stdout, stderr, returncode, hint}. If the jump proxy
    rejects us (expired Kerberos ticket), runs `kinit` once in the terminal and retries."""
    proxy = SSH_JUMP_PROXY[region]
    user = _ssh_user()
    cmd = ["ssh",
           "-o", "BatchMode=yes",
           "-o", "ConnectTimeout=20",
           # Same trust-on-first-use behaviour as the runbook's manual ssh
           # ("Permanently added ... to the list of known hosts").
           "-o", "StrictHostKeyChecking=accept-new",
           "-J", f"{user}@{proxy}",
           f"root@{ip}", command]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "category": "timeout", "stdout": "", "stderr": "",
                "returncode": None, "hint": f"No answer within {timeout}s."}
    except FileNotFoundError:
        return {"ok": False, "category": "other", "stdout": "", "stderr": "",
                "returncode": None, "hint": "ssh is not installed / not on PATH."}

    if cp.returncode == 0:
        return {"ok": True, "category": "ok", "stdout": cp.stdout, "stderr": cp.stderr,
                "returncode": 0, "hint": ""}

    category = classify_ssh_failure(cp.stderr, user, proxy)
    if category == "jump_auth" and retry_kinit:
        print(f"\n  Jump proxy rejected {user}@{proxy} — Kerberos ticket likely expired.")
        print(f"  Running: kinit {user}@{KERBEROS_REALM}  (enter your password)")
        subprocess.run(["kinit", f"{user}@{KERBEROS_REALM}"])
        return ssh_run(ip, command, region, timeout, retry_kinit=False)

    hints = {
        "jump_auth": f"Rejected at the jump proxy even after kinit — check the username ({user}).",
        "host_permission": "Rejected by the host: Orthrus / XFlow operator permission is probably "
                           "missing. See the links below.",
        "unreachable": "Host not reachable over SSH. Per the runbook, check whether the agent was "
                       "issued; if not, an OCI manager reinstall may be needed (never done automatically).",
        "host_key": f"Host key changed (common after a reinstall). If expected: ssh-keygen -R {ip}",
        "other": "Unclassified ssh failure — see stderr.",
    }
    return {"ok": False, "category": category, "stdout": cp.stdout, "stderr": cp.stderr,
            "returncode": cp.returncode, "hint": hints.get(category, "")}


def do_ssh_test():
    """Menu H: one-host SSH check — runs `hostname` and explains any failure."""
    print("\nRegion:\n  1) I18N (SG jump proxy)\n  2) EUTTP (IE jump proxy)")
    region = {"1": "i18n", "2": "euttp"}.get(input("Choose [1]: ").strip() or "1")
    if not region:
        print("Invalid choice.")
        return
    ip = input("Host IP: ").strip()
    if not ip:
        return
    print(f"\n  Running hostname on {ip} via {SSH_JUMP_PROXY[region]} ...")
    res = ssh_run(ip, "hostname", region)
    if res["ok"]:
        lines = [ln for ln in res["stdout"].strip().splitlines() if ln.strip()]
        print(f"  OK — host answered: {lines[-1] if lines else '(empty)'}")
        return
    print(f"  FAILED ({res['category']}): {res['hint']}")
    if res["category"] == "host_permission":
        for line in SSH_PERMISSION_HELP[region]:
            print("    " + line)
    err = (res["stderr"] or "").strip()
    if err:
        print("  --- ssh stderr ---")
        print("  " + err.replace("\n", "\n  "))



def main():
    while True:
        latest = find_latest_ticket_export()
        latest_name = latest.name if latest else "(none found in this folder)"

        print()
        print("=" * 50)
        print("  Ticket / Port-22 / Reboot Tools")
        print("=" * 50)
        print()
        print("  1) Filter tickets + Port-22 check")
        print("  E) Export from web (choose I18N, EUTTP, or BOTH), then filter + Port-22 check")
        print("  2) Reboot Unreachable (from last ticketq result)")
        print("  3) Reboot by manual IP input")
        print("  4) Reinstall by manual IP input")
        print("  5) Recreate by manual IP input")
        print("  6) Filter only (skip port check)")
        print("  7) Recreate ticket-flagged hosts (from last ticketq result)")
        print("  G) GPU shapes (L40S-NC.4 / A10.4 / T1.2): export -> mark unhealthy -> Recreate (I18N)")
        print("  H) SSH test: run `hostname` on a host via the jump proxy (Kerberos)")
        print()
        print("  D) Disk/NVMe: maintenance check -> scheduled Excel + Aries check -> final Excel")
        print("  N) OS EIPv4/EIPv6 unreachable: secondary IP SAOS -> NIC Aries -> Recreate/Reinstall -> recheck")
        print("  R) NVMe QID timeout/reset: Aries check (660s timeout) -> Recreate/OCI SR/Reinstall")
        print("  K) [Standalone] Disk/NVMe Aries check by IP — no ticket lookup, just precheck/deploy/poll")
        print("  W) [Standalone] NIC-state Aries check by IP — no ticket lookup, just precheck/deploy/poll")
        print("  L) Show saved generated SR fields (IP / ticket / deployment / job key)")
        print("  S) [LEGACY] Fill Lark SR form (from last option D drafts) — never submits")
        print("  9) Dry-run (reboot / recreate previews)")
        print("  P) Poll tracked IPs now (check status / auto-escalate / dual-IP reinstalls)")
        print("  T) [DEBUG] Test Alto polling against a real ticket")
        print("  F) [DEBUG] Test filesystem mount-point lookup")
        print("  C) Clear tracked IP(s) from the pipeline")
        print()
        print("  0) Exit")
        print()
        print("-" * 50)
        print("  NOTE: Please retrieve / export the latest tickets")
        print("        Excel before running options 1 or 6.")
        print(f"  Current auto-detect file: {latest_name}")

        summary = pipeline_attention_summary()
        if summary["total"] == 0:
            print("  Pipeline: nothing currently tracked.")
        else:
            parts = []
            if summary["running_count"]:
                parts.append(f"{summary['running_count']} running")
            line = f"  Pipeline: {summary['total']} tracked"
            if parts:
                line += " (" + ", ".join(parts) + ")"
            print(line)
            if summary["needs_attention"]:
                for ip, entry in summary["needs_attention"].items():
                    stage = entry.get("stage", "?")
                    state = entry.get("state", "?")
                    state_label = {
                        "awaiting_recreate_approval": "awaiting recreate approval",
                        "awaiting_review": "awaiting Alto review",
                    }.get(state, state)
                    print(f"  ⚠ Needs attention: {ip} ({stage}, {state_label})")

        if _dual_ip_pending:
            dual_running = sum(1 for e in _dual_ip_pending.values() if e.get("state") == "running")
            print(f"  Dual-IP: {len(_dual_ip_pending)} reinstall(s) tracked "
                  f"({dual_running} running) — press P to check.")

        print("-" * 50)
        print()

        choice = input("Select option: ").strip()

        try:
            if choice == "1":
                do_ticketq(skip_check=False)
            elif choice.lower() == "e":
                do_ticketq(skip_check=False, auto_export=True)
            elif choice == "2":
                do_reboot_from_excel(dry_run=False)
            elif choice == "3":
                do_reboot_manual(dry_run=False)
            elif choice == "4":
                do_reinstall_manual(dry_run=False)
            elif choice == "5":
                do_recreate_manual(dry_run=False)
            elif choice == "6":
                do_ticketq(skip_check=True)
            elif choice == "7":
                do_recreate_from_tickets(dry_run=False)
            elif choice.lower() == "g":
                do_gpu_unhealthy_recreate_workflow(dry_run=False)
            elif choice.lower() == "h":
                do_ssh_test()
            elif choice.lower() == "d":
                do_disk_lost_aries_workflow()
            elif choice.lower() == "n":
                do_dual_ip_unreachable_workflow()
            elif choice.lower() == "r":
                do_nvme_timeout_reset_workflow()
            elif choice.lower() == "k":
                do_aries_disk_check_manual()
            elif choice.lower() == "w":
                do_aries_nic_check_manual()
            elif choice.lower() == "l":
                do_show_saved_aries_sr_fields()
            elif choice.lower() == "s":
                do_fill_sr_form_test()
            elif choice == "9":
                do_dry_run_menu()
            elif choice.lower() == "p":
                do_pipeline_poll_now()
            elif choice.lower() == "t":
                do_alto_debug_test()
            elif choice.lower() == "f":
                do_filesystem_debug_test()
            elif choice.lower() == "c":
                do_pipeline_clear()
            elif choice == "0":
                print("Closing browser (if open)...")
                close_browser()
                print("Bye.")
                break
            else:
                print("Invalid option.")
        except KeyboardInterrupt:
            print("\nCancelled.")
        except Exception as e:
            print(f"\nError: {e}")


if __name__ == "__main__":
    try:
        main()
    finally:
        close_browser()