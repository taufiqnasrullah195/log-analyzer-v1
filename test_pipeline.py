"""Regression tests for the auto-scan pipeline.

Stdlib only (unittest) — no pytest dependency, runs with plain `python`.

    python test_pipeline.py            # run everything
    python test_pipeline.py -v         # verbose
"""
from __future__ import annotations

import os
import tempfile
import time
import unittest
from unittest import mock

import auto_resolve
import auto_scan
import batch_report
import fix_generator
import issue_rules
import menu
import notifier
import router_log_grab


# ── fixtures ────────────────────────────────────────────────────────────────

FLAP_LOG = """*Mar  1 00:01:10.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/0, changed state to down
*Mar  1 00:01:12.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/0, changed state to up
*Mar  1 00:02:20.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/0, changed state to down
*Mar  1 00:02:22.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/0, changed state to up
"""

SINGLE_FLAP_LOG = """*Mar  1 00:01:10.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/0, changed state to down
"""

CRITICAL_LOG = """*Mar  1 00:06:00.222: %SYS-2-MALLOCFAIL: Memory allocation of 10240 bytes failed from 0x60305D5C, pool Processor
*Mar  1 00:04:01.001: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 192.168.1.11] [localport: 22]
*Mar  1 00:04:05.002: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 192.168.1.11] [localport: 22]
*Mar  1 00:04:09.003: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 192.168.1.11] [localport: 22]
"""

BENIGN_LOG = """*Mar  1 00:02:11.456: %SYS-5-CONFIG_I: Configured from console by console
"""

# Verbatim from a real Packet Tracer Router0 CLI console after
# `shutdown` / `no shutdown` cycles. Note PT emits LINK-5-CHANGED for BOTH
# directions, where real IOS would emit LINK-5-CHANGED (admin down) and
# LINK-3-UPDOWN (back up) — so the flap rule must accept both.
PT_SHUTDOWN_LOG = """%LINK-5-CHANGED: Interface GigabitEthernet0/0, changed state to administratively down
%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/0, changed state to down
%LINK-5-CHANGED: Interface GigabitEthernet0/0, changed state to up
%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/0, changed state to up
%LINK-5-CHANGED: Interface GigabitEthernet0/0, changed state to administratively down
%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/0, changed state to down
%LINK-5-CHANGED: Interface GigabitEthernet0/0, changed state to up
%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/0, changed state to up
%SYS-5-CONFIG_I: Configured from console by console
"""


def _ids(issues: list[issue_rules.DetectedIssue]) -> set[str]:
    return {i.rule.id for i in issues}


# ── issue_rules ─────────────────────────────────────────────────────────────

class TestIssueRules(unittest.TestCase):

    def test_flapping_fires_at_threshold(self):
        issues = issue_rules.scan(FLAP_LOG)
        self.assertIn("interface_flap", _ids(issues))

    def test_single_flap_does_not_fire(self):
        """One LINK-3-UPDOWN is a routine cable reseat, not a flap."""
        issues = issue_rules.scan(SINGLE_FLAP_LOG)
        self.assertNotIn("interface_flap", _ids(issues))

    def test_interface_entity_extracted(self):
        issue = next(i for i in issue_rules.scan(FLAP_LOG) if i.rule.id == "interface_flap")
        self.assertIn("GigabitEthernet0/0", issue.entities)

    def test_memory_is_critical(self):
        issues = issue_rules.scan(CRITICAL_LOG)
        self.assertIn("memory_exhaustion", _ids(issues))
        self.assertEqual(issue_rules.worst_severity(issues), "CRITICAL")

    def test_auth_fail_needs_three_hits(self):
        one = "*Mar  1 00:04:01.001: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [Source: 10.0.0.9]"
        self.assertNotIn("auth_fail", _ids(issue_rules.scan(one)))
        self.assertIn("auth_fail", _ids(issue_rules.scan(CRITICAL_LOG)))

    def test_auth_fail_extracts_source_ip(self):
        issue = next(i for i in issue_rules.scan(CRITICAL_LOG) if i.rule.id == "auth_fail")
        self.assertIn("192.168.1.11", issue.entities)

    def test_benign_log_has_no_warning(self):
        issues = issue_rules.scan(BENIGN_LOG)
        self.assertEqual(issue_rules.worst_severity(issues), "INFO")

    def test_empty_log(self):
        self.assertEqual(issue_rules.scan(""), [])
        self.assertEqual(issue_rules.worst_severity([]), "INFO")

    def test_severity_ordering(self):
        issues = issue_rules.scan(CRITICAL_LOG)
        order = [issue_rules.SEVERITY_ORDER[i.rule.severity] for i in issues]
        self.assertEqual(order, sorted(order), "issues must be severity-sorted")

    def test_pt_link5_changed_counts_as_flap(self):
        """REGRESSION: Packet Tracer emits LINK-5-CHANGED for shutdown/no
        shutdown. Matching only LINK-3-UPDOWN silently missed every PT flap."""
        self.assertIn("interface_flap", _ids(issue_rules.scan(PT_SHUTDOWN_LOG)))

    def test_admin_shutdown_detected_and_entity_extracted(self):
        issue = next(i for i in issue_rules.scan(PT_SHUTDOWN_LOG)
                     if i.rule.id == "admin_shutdown")
        self.assertIn("GigabitEthernet0/0", issue.entities)


# ── fix_generator ───────────────────────────────────────────────────────────

class TestFixGenerator(unittest.TestCase):

    def setUp(self):
        self.issues = issue_rules.scan(CRITICAL_LOG)
        self.script = fix_generator.build_script(self.issues)

    def test_no_raw_placeholders_leak(self):
        """A {iface} reaching the operator is a bug, not a template."""
        self.assertNotIn("{iface}", self.script)
        self.assertNotIn("{ip}", self.script)

    def test_entity_substituted_into_commands(self):
        self.assertIn("192.168.1.11", self.script)

    def test_critical_has_no_auto_fix(self):
        """Memory exhaustion must never ship an automatic remedy."""
        plan = fix_generator.FIX_LIBRARY["memory_exhaustion"]
        self.assertFalse(plan.auto_safe)
        self.assertEqual(plan.fix, ())

    def test_auto_applicable_excludes_critical(self):
        safe_ids = {i.rule.id for i in fix_generator.auto_applicable(self.issues)}
        self.assertNotIn("memory_exhaustion", safe_ids)

    def test_flap_is_auto_applicable(self):
        issues = issue_rules.scan(FLAP_LOG)
        safe_ids = {i.rule.id for i in fix_generator.auto_applicable(issues)}
        self.assertIn("interface_flap", safe_ids)

    def test_admin_shutdown_is_not_auto_applicable(self):
        """Re-enabling a port someone deliberately disabled must stay manual."""
        plan = fix_generator.FIX_LIBRARY["admin_shutdown"]
        self.assertFalse(plan.auto_safe)
        self.assertTrue(plan.fix)

    def test_script_has_diagnose_and_fix_sections(self):
        self.assertIn("# --- diagnose", self.script)
        self.assertIn("# --- fix", self.script)

    def test_empty_issue_list_still_renders(self):
        out = fix_generator.build_script([])
        self.assertIn("Nothing to remediate", out)

    def test_every_rule_id_has_a_plan(self):
        """A rule without a plan silently degrades to 'no remediation mapped'."""
        missing = [r.id for r in issue_rules.RULES if r.id not in fix_generator.FIX_LIBRARY]
        self.assertEqual(missing, [], f"rules missing a fix plan: {missing}")


# ── auto_scan candidate filter (regression) ─────────────────────────────────

class TestCandidateFilter(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _touch(self, name: str) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("x")
        return path

    def test_picks_log_files(self):
        self._touch("a.log")
        self._touch("b.txt")
        picked = [os.path.basename(p) for p in auto_scan._candidates(self.dir)]
        self.assertCountEqual(picked, ["a.log", "b.txt"])

    def test_skips_own_fix_output(self):
        """REGRESSION: the watcher writing *.fix.txt into the watched folder
        used to re-ingest it and emit name.fix.fix.fix.txt forever."""
        self._touch("router.log")
        self._touch("router.fix.txt")
        self._touch("router.fix.fix.fix.txt")
        picked = [os.path.basename(p) for p in auto_scan._candidates(self.dir)]
        self.assertEqual(picked, ["router.log"])

    def test_skips_dotfiles(self):
        self._touch(".autoscan_state.json")
        self._touch("real.log")
        picked = [os.path.basename(p) for p in auto_scan._candidates(self.dir)]
        self.assertEqual(picked, ["real.log"])

    def test_skips_subdirectories(self):
        os.makedirs(os.path.join(self.dir, "fixes"))
        self._touch("real.log")
        picked = [os.path.basename(p) for p in auto_scan._candidates(self.dir)]
        self.assertEqual(picked, ["real.log"])

    def test_skips_unrelated_extensions(self):
        self._touch("notes.md")
        self._touch("data.csv")
        self.assertEqual(auto_scan._candidates(self.dir), [])


# ── auto_scan end-to-end ────────────────────────────────────────────────────

class TestEndToEnd(unittest.TestCase):

    def test_process_writes_fix_script(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "r.log")
            out = os.path.join(d, "r.fix.txt")
            with open(log, "w", encoding="utf-8") as fh:
                fh.write(CRITICAL_LOG)
            issues, script = auto_scan.process(log, use_llm=False, lang="id", fix_out=out)
            self.assertTrue(issues)
            self.assertTrue(os.path.isfile(out))
            self.assertIn("Auto Fix Script", script)

    def test_process_handles_empty_file(self):
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "empty.log")
            open(log, "w").close()
            issues, script = auto_scan.process(log, use_llm=False, lang="id", fix_out=None)
            self.assertEqual(issues, [])
            self.assertEqual(script, "")


# ── vendor coverage ─────────────────────────────────────────────────────────

# Verbatim MikroTik RouterOS log: "topic,severity message", no %MNEMONIC.
MIKROTIK_LOG = """system,error,critical login failure for user admin from 192.168.88.5 via telnet
system,error,critical login failure for user admin from 192.168.88.5 via telnet
system,error,critical login failure for user admin from 192.168.88.5 via ssh
interface,info ether1 link down
interface,info ether1 link up
interface,info ether1 link down
interface,info ether1 link up
interface,info ether1 link down
interface,info ether1 link up
"""

# Verbatim Huawei VRP log: %%01FACILITY/SEV/MNEMONIC, interface named mid-sentence.
HUAWEI_LOG = """%%01IFNET/4/LINK_STATE(l)[0]:The line protocol IP on the interface GigabitEthernet0/0/1 has entered the DOWN state.
%%01IFNET/4/LINK_STATE(l)[1]:The line protocol IP on the interface GigabitEthernet0/0/1 has entered the UP state.
%%01IFNET/4/LINK_STATE(l)[2]:The line protocol IP on the interface GigabitEthernet0/0/1 has entered the DOWN state.
%%01IFNET/4/LINK_STATE(l)[3]:The line protocol IP on the interface GigabitEthernet0/0/1 has entered the UP state.
"""


class TestVendorCoverage(unittest.TestCase):
    """Each vendor phrases the same event differently; the rules must follow."""

    def test_mikrotik_vendor_detected(self):
        from analyzer import detect_vendor
        self.assertEqual(detect_vendor(MIKROTIK_LOG).vendor, "MikroTik RouterOS")

    def test_mikrotik_link_change_fires(self):
        self.assertIn("mikrotik_link", _ids(issue_rules.scan(MIKROTIK_LOG)))

    def test_mikrotik_interface_entity_extracted(self):
        issue = next(i for i in issue_rules.scan(MIKROTIK_LOG)
                     if i.rule.id == "mikrotik_link")
        self.assertIn("ether1", issue.entities)

    def test_mikrotik_login_failure_counts_as_auth_fail(self):
        self.assertIn("auth_fail", _ids(issue_rules.scan(MIKROTIK_LOG)))

    def test_mikrotik_auth_source_ip_extracted(self):
        issue = next(i for i in issue_rules.scan(MIKROTIK_LOG)
                     if i.rule.id == "auth_fail")
        self.assertIn("192.168.88.5", issue.entities)

    def test_huawei_vendor_detected(self):
        from analyzer import detect_vendor
        self.assertEqual(detect_vendor(HUAWEI_LOG).vendor, "Huawei VRP")

    def test_huawei_link_state_fires_flap(self):
        self.assertIn("interface_flap", _ids(issue_rules.scan(HUAWEI_LOG)))

    def test_huawei_interface_named_mid_sentence_is_extracted(self):
        """Huawei says 'on the interface X', not 'Interface X'."""
        issue = next(i for i in issue_rules.scan(HUAWEI_LOG)
                     if i.rule.id == "interface_flap")
        self.assertIn("GigabitEthernet0/0/1", issue.entities)


# ── notifier ────────────────────────────────────────────────────────────────

class TestNotifier(unittest.TestCase):

    def test_not_configured_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(notifier.configured())

    def test_dry_run_returns_false_without_raising(self):
        """An unconfigured channel must stay silent, never raise."""
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(notifier.notify("ping"))

    def test_summary_lists_only_critical_and_warning(self):
        reports = [
            batch_report.DeviceReport("a.log", "core-sw1", "Cisco IOS", 10, "CRITICAL",
                                      issue_rules.scan(CRITICAL_LOG)),
            batch_report.DeviceReport("b.log", "edge-rtr1", "Cisco IOS", 5, "INFO", []),
        ]
        body = notifier.format_summary(reports, "logs")
        self.assertIn("core-sw1", body)
        self.assertNotIn("edge-rtr1", body)

    def test_summary_html_escapes_device_names(self):
        reports = [batch_report.DeviceReport("x", "core<script>", "Cisco IOS", 1,
                                             "CRITICAL", [])]
        self.assertNotIn("<script>", notifier.format_summary(reports, "logs"))
        self.assertIn("&lt;script&gt;", notifier.format_summary(reports, "logs"))


# ── batch_report ────────────────────────────────────────────────────────────

class TestBatchReport(unittest.TestCase):

    def test_collect_skips_fix_output_and_dotdirs(self):
        with tempfile.TemporaryDirectory() as d:
            for n in ("a.log", "a.fix.txt", ".hidden.log", "notes.md"):
                open(os.path.join(d, n), "w").close()
            os.makedirs(os.path.join(d, "fixes"))
            open(os.path.join(d, "fixes", "b.log"), "w").close()
            picked = [os.path.basename(p) for p in batch_report.collect(d)]
            self.assertEqual(picked, ["a.log"])

    def test_rank_puts_critical_first(self):
        crit = batch_report.DeviceReport("a", "a", "v", 1, "CRITICAL", [])
        info = batch_report.DeviceReport("b", "b", "v", 1, "INFO", [])
        self.assertLess(crit.rank, info.rank)


# ── menu (control panel) ────────────────────────────────────────────────────

class TestMenu(unittest.TestCase):
    """menu.py is interactive, so cover its pure helpers, not the loop."""

    def test_log_files_skips_fix_output_and_fixes_dir(self):
        with tempfile.TemporaryDirectory() as d:
            for n in ("a.log", "a.fix.txt", "notes.md"):
                open(os.path.join(d, n), "w").close()
            os.makedirs(os.path.join(d, "fixes"))
            open(os.path.join(d, "fixes", "b.log"), "w").close()
            picked = [os.path.basename(p) for p in menu.log_files(d)]
            self.assertEqual(picked, ["a.log"])

    def test_log_files_on_missing_dir_is_empty_not_a_crash(self):
        missing = os.path.join(tempfile.gettempdir(), "definitely_not_here_xyz")
        self.assertEqual(menu.log_files(missing), [])

    def test_counts_reads_the_real_modules(self):
        rules, vendors = menu.counts()
        self.assertGreater(rules, 0)
        self.assertGreater(vendors, 0)

    def test_telegram_flag_follows_env(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(menu.telegram_on())
        with mock.patch.dict(os.environ,
                             {"TELEGRAM_BOT_TOKEN": "t", "TELEGRAM_CHAT_ID": "1"},
                             clear=True):
            self.assertTrue(menu.telegram_on())


# ── auto_resolve (the risky one — gate everything) ──────────────────────────

class TestAutoResolve(unittest.TestCase):

    def test_warning_device_gets_commands(self):
        plan = auto_resolve.build_plan(FLAP_LOG, "sw1")
        self.assertTrue(plan.commands)
        self.assertIn("interface_flap", plan.applied_ids)

    def test_critical_device_is_refused_even_when_a_safe_fix_exists(self):
        """CRITICAL + a flapping port: the flap is auto_safe on its own, but a
        device already in a critical state must not be touched at all. This
        fixture is the ONLY way to observe the gate — a critical log with no
        auto_safe issue hits the 'nothing auto_safe' branch first and proves
        nothing about it."""
        plan = auto_resolve.build_plan(CRITICAL_LOG + FLAP_LOG, "rtr1")
        self.assertEqual(auto_resolve.build_plan(FLAP_LOG, "rtr1").commands != [],
                         True, "flap alone must be applicable")
        self.assertEqual(plan.commands, [])
        self.assertEqual(plan.applied_ids, [])
        self.assertTrue(any("CRITICAL" in s for s in plan.skipped))

    def test_manually_gated_issue_never_reaches_commands(self):
        """The ACL half of the auth_fail plan is human-only; it must not leak
        into anything an executor would run."""
        plan = auto_resolve.build_plan(CRITICAL_LOG + FLAP_LOG, "rtr1")
        self.assertNotIn("access-list", "\n".join(plan.commands))
        self.assertNotIn("auth_fail", plan.applied_ids)

    def test_no_issues_yields_empty_plan(self):
        plan = auto_resolve.build_plan("", "x")
        self.assertEqual(plan.commands, [])
        self.assertTrue(plan.skipped)

    def test_commands_are_fully_substituted(self):
        plan = auto_resolve.build_plan(FLAP_LOG, "sw1")
        joined = "\n".join(plan.commands)
        self.assertNotIn("{iface}", joined)
        self.assertIn("GigabitEthernet0/0", joined)

    def test_lock_is_exclusive_and_releasable(self):
        dev = "unittest-device-xyz"
        auto_resolve.release_lock(dev)
        self.assertTrue(auto_resolve.acquire_lock(dev))
        self.assertFalse(auto_resolve.acquire_lock(dev), "second acquire must fail")
        auto_resolve.release_lock(dev)
        self.assertTrue(auto_resolve.acquire_lock(dev), "must be reusable after release")
        auto_resolve.release_lock(dev)

    def test_transport_registry_has_the_three_expected(self):
        self.assertEqual(set(auto_resolve.TRANSPORTS), {"dry-run", "clipboard", "ssh"})

    def test_only_ssh_is_apply_gated(self):
        self.assertTrue(auto_resolve.TRANSPORTS["ssh"].needs_apply)
        self.assertFalse(auto_resolve.TRANSPORTS["dry-run"].needs_apply)
        self.assertFalse(auto_resolve.TRANSPORTS["clipboard"].needs_apply)


# ── router_log_grab (the denylist is the product) ───────────────────────────

class TestRouterLogGrab(unittest.TestCase):
    """Filenames below are the shapes actually present in a real Downloads
    folder. A watcher that ingests them would ship recovery phrases and wallet
    backup codes to the analyzer, and with --llm to a third-party model."""

    SECRETS = [
        "bitgo-recovery-codes-someone@example.com.txt",
        "backup_recovery_phrase_someone@gmail.com.txt",
        "Backup-codes-example.txt",
        "wallet-seed-phrase.txt",
        "id_rsa.pem",
        "api-key-prod.txt",
        "passwords.txt",
        "2fa-backup-codes.log",
    ]

    LOGS = [
        "syslog.txt",
        "SystemLog_20261024.log",
        "router_log_export.txt",
        "diagnostics.csv",
        "MR3000X_syslog.log",
    ]

    def test_every_secret_shape_is_refused(self):
        for name in self.SECRETS:
            with self.subTest(name=name):
                self.assertIsNotNone(router_log_grab.is_secret(name),
                                     f"{name} must be refused")

    def test_real_router_log_names_pass_the_denylist(self):
        for name in self.LOGS:
            with self.subTest(name=name):
                self.assertIsNone(router_log_grab.is_secret(name),
                                  f"{name} is a legitimate log export")

    def test_looks_like_log_accepts_exports(self):
        for name in self.LOGS:
            with self.subTest(name=name):
                self.assertTrue(router_log_grab.looks_like_log(name))

    def test_looks_like_log_rejects_our_own_output(self):
        self.assertFalse(router_log_grab.looks_like_log("router.fix.txt"))
        self.assertFalse(router_log_grab.looks_like_log("notes.md"))

    def test_find_candidates_excludes_secrets_and_reports_refusals(self):
        with tempfile.TemporaryDirectory() as d:
            for n in self.SECRETS + self.LOGS:
                open(os.path.join(d, n), "w").close()
            found, refused = router_log_grab.find_candidates([d], 60 * 24 * 365)
            names = [c["name"] for c in found]
            for n in self.SECRETS:
                with self.subTest(secret=n):
                    self.assertNotIn(n, names, "a refused file must never be a candidate")
            for n in self.LOGS:
                with self.subTest(log=n):
                    self.assertIn(n, names)
            self.assertTrue(refused, "refusals must be reported, not silent")

    def test_find_candidates_respects_the_age_window(self):
        """An old secret is still never copied; an old log is simply out of scope."""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "syslog.txt")
            open(p, "w").close()
            old = time.time() - 10 * 24 * 3600
            os.utime(p, (old, old))
            found, _ = router_log_grab.find_candidates([d], 60)
            self.assertEqual(found, [])


# ── OpenWrt / LuCI (the format a MERCUSYS/TP-Link router actually emits) ────

# Verbatim logread format: `facility.level daemon[pid]: message`, no Cisco
# mnemonic anywhere. Every rule above this one is blind to it.
OPENWRT_LOG = """Sat Oct 24 16:00:01 2026 daemon.notice netifd: Network device 'eth0' link is down
Sat Oct 24 16:00:03 2026 daemon.notice netifd: Network device 'eth0' link is up
Sat Oct 24 16:00:05 2026 auth.info hostapd: wlan0: STA aa:bb:cc:dd:ee:01 IEEE 802.11: authenticated
Sat Oct 24 16:00:06 2026 auth.info hostapd: wlan0: STA aa:bb:cc:dd:ee:01 IEEE 802.11: deauthenticated
Sat Oct 24 16:00:09 2026 auth.info hostapd: wlan0: STA aa:bb:cc:dd:ee:01 IEEE 802.11: deauthenticated
Sat Oct 24 16:00:12 2026 auth.info hostapd: wlan0: STA aa:bb:cc:dd:ee:01 IEEE 802.11: deauthenticated
Sat Oct 24 16:00:20 2026 auth.warn hostapd: wlan0: STA aa:bb:cc:dd:ee:02 IEEE 802.11: authentication failed
Sat Oct 24 16:00:22 2026 auth.warn hostapd: wlan0: STA aa:bb:cc:dd:ee:02 IEEE 802.11: authentication failed
Sat Oct 24 16:00:24 2026 auth.warn hostapd: wlan0: STA aa:bb:cc:dd:ee:02 IEEE 802.11: authentication failed
Sat Oct 24 16:00:31 2026 daemon.warn dnsmasq[1234]: no upstream servers configured
Sat Oct 24 16:00:33 2026 daemon.err dnsmasq-dhcp[1234]: DHCPACK(br-lan) failed: Network unreachable
Sat Oct 24 16:00:40 2026 daemon.info dnsmasq-dhcp[1234]: DHCPACK(br-lan) 192.168.1.121 aa:bb:cc:dd:ee:03 taufi-laptop
"""


class TestOpenWrt(unittest.TestCase):
    """A MERCUSYS/TP-Link/GL.iNet router speaks this dialect, not IOS."""

    def test_vendor_is_detected_as_openwrt(self):
        from analyzer import detect_vendor
        self.assertEqual(detect_vendor(OPENWRT_LOG).vendor, "OpenWrt / LuCI")

    def test_wan_link_down_fires_and_names_the_device(self):
        issues = {i.rule.id: i for i in issue_rules.scan(OPENWRT_LOG)}
        self.assertIn("wan_link_down", issues)
        self.assertIn("eth0", issues["wan_link_down"].entities)

    def test_wifi_deauth_fires(self):
        self.assertIn("wifi_deauth", _ids(issue_rules.scan(OPENWRT_LOG)))

    def test_wifi_deauth_extracts_the_sta_mac(self):
        issue = next(i for i in issue_rules.scan(OPENWRT_LOG)
                     if i.rule.id == "wifi_deauth")
        self.assertIn("aa:bb:cc:dd:ee:01", issue.entities)

    def test_wifi_auth_fail_fires(self):
        self.assertIn("wifi_auth_fail", _ids(issue_rules.scan(OPENWRT_LOG)))

    def test_dnsmasq_error_fires(self):
        self.assertIn("dnsmasq_error", _ids(issue_rules.scan(OPENWRT_LOG)))

    def test_openwrt_log_does_not_masquerade_as_cisco(self):
        """The generic Cisco mnemonic rule must not claim this log."""
        self.assertNotIn("config_change", _ids(issue_rules.scan(OPENWRT_LOG)))

    def test_openwrt_log_produces_a_usable_fix_script(self):
        script = fix_generator.build_script(issue_rules.scan(OPENWRT_LOG),
                                            vendor="OpenWrt / LuCI")
        self.assertIn("hostapd", script.lower())
        self.assertIn("netifd", script.lower())


class TestRuleInvariants(unittest.TestCase):
    """Every rule must be actionable, or it is just noise in the report."""

    def test_every_rule_has_a_fix_plan(self):
        missing = [r.id for r in issue_rules.RULES
                   if r.id not in fix_generator.FIX_LIBRARY]
        self.assertEqual(missing, [], f"rules without a fix plan: {missing}")

    def test_no_orphan_fix_plans(self):
        known = {r.id for r in issue_rules.RULES}
        orphans = [k for k in fix_generator.FIX_LIBRARY if k not in known]
        self.assertEqual(orphans, [], f"fix plans without a rule: {orphans}")

    def test_critical_issues_are_never_marked_auto_safe(self):
        for rule in issue_rules.RULES:
            if rule.severity == "CRITICAL":
                with self.subTest(rule=rule.id):
                    self.assertFalse(fix_generator.FIX_LIBRARY[rule.id].auto_safe,
                                     f"CRITICAL rule {rule.id} must never auto-apply")


class TestPlaceholderFill(unittest.TestCase):
    """_fill ran over every fix command; a too-eager substitution silently
    corrupted a real command instead of failing loudly."""

    def test_regex_quantifiers_are_left_alone(self):
        src = "logread | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | sort | uniq -c"
        out = fix_generator._fill(src, {})
        self.assertEqual(out, src)

    def test_a_known_key_is_substituted(self):
        self.assertEqual(fix_generator._fill("no shut {iface}", {"iface": "Gi0/1"}),
                         "no shut Gi0/1")

    def test_an_unmapped_known_key_is_visible_not_empty(self):
        self.assertEqual(fix_generator._fill("enable {iface}", {}), "enable <iface>")

    def test_no_rendered_plan_leaves_a_broken_quantifier(self):
        """Regression: every shipped command must survive _fill intact."""
        for rule_id, plan in fix_generator.FIX_LIBRARY.items():
            for cmd in tuple(plan.diagnose) + tuple(plan.fix):
                with self.subTest(rule=rule_id, cmd=cmd):
                    out = fix_generator._fill(cmd, {"iface": "Gi0/1", "ip": "10.0.0.1"})
                    self.assertNotIn("<2>", out)
                    self.assertNotIn("<5>", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)