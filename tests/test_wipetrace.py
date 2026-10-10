#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""합성 자료로 PoC 동작을 확인하는 단위 테스트:  python -m unittest tests/test_wipetrace.py"""
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import wipetrace  # noqa: E402


class TestWipetrace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, os.path.join(HERE, "make_synthetic.py")], check=True)
        cls.sig = wipetrace.load_signatures(os.path.join(ROOT, "signatures.yaml"))
        cls.runs = os.path.join(HERE, "synthetic_runs")

    def run_case(self, name):
        return wipetrace.analyze(os.path.join(self.runs, name), self.sig)

    def test_shared_folder_path_is_not_presence(self):
        # 공유 폴더에 놓인 설치 파일 이름은 존재 근거가 아니고, 설치된 본체 경로는 존재 근거다
        share = r"\\vmware-host\Shared Folders\installers\BleachBit-6.0.4-setup.exe"
        local = r"C:\Program Files\BleachBit\bleachbit.exe"
        dq = {"inputs": {"amcache": {"rows": None}, "mft": {"rows": None}, "registry": {"rows": [
            ("reg.csv", 2, {"Description": "AppCompatCache", "ValueData": share}),
            ("reg.csv", 3, {"Description": "AppCompatCache", "ValueData": local})]}}}
        self.assertTrue(self.sig["rules"]["ignore_env_path_keywords"])
        found = wipetrace.find_presence(None, self.sig, dq)
        self.assertEqual([h["row"] for h in found["bleachbit"]], [3])

    def test_shared_folder_installer_is_not_execution(self):
        # 설치 파일 이름이 본체와 같아도(eraser.exe) 공유 폴더 경로면 실행 흔적으로 세지 않는다. 표기 세 가지 모두.
        ua = {"Description": "UserAssist", "ValueData2": "Last executed: 2026-10-05 09:00:00.0000000"}
        rows = [("reg.csv", 2, dict(ua, ValueData=r"\\vmware-host\Shared Folders\installers\eraser.exe")),
                ("reg.csv", 3, {"Description": "Background Activity Moderator (BAM)",
                                "ValueData": r"Program: \Device\Mup\vmware-host\Shared Folders\installers\eraser.exe"}),
                ("reg.csv", 4, dict(ua, ValueData=r"UNC\vmware-host\Shared Folders\installers\eraser.exe")),
                ("reg.csv", 5, dict(ua, ValueData=r"C:\Program Files\Eraser\Eraser.exe"))]
        dq = {"inputs": {"prefetch": {"rows": None}, "registry": {"rows": rows}}}
        found = wipetrace.find_execution(None, self.sig, dq)
        self.assertEqual([h["row"] for h in found["eraser"]], [5])

    def test_baseline(self):
        r = self.run_case("R01")
        self.assertEqual(r["stage"], 0)
        self.assertEqual(r["alerts"], {"exec": 0, "journal": 0, "both": 0})

    def test_install_only_is_presence(self):
        r = self.run_case("R02")
        self.assertEqual(r["stage"], 1)
        self.assertIn("eraser", r["presence"])
        self.assertNotIn("eraser", r["execution"])  # 설치 프로그램 Prefetch는 본체 실행이 아님

    def test_exec_only(self):
        r = self.run_case("R03")
        self.assertEqual(r["stage"], 2)
        self.assertEqual(r["alerts"]["exec"], 1)
        self.assertEqual(r["alerts"]["both"], 0)

    def test_shift_delete_not_wipe(self):
        self.assertEqual(self.run_case("R04")["alerts"]["journal"], 0)

    def test_recycle_bin_not_wipe(self):
        self.assertEqual(self.run_case("R05")["alerts"]["journal"], 0)

    def test_sdelete_linked(self):
        r = self.run_case("R06")
        self.assertEqual(r["stage"], 4)
        self.assertEqual(r["candidate_tools"], ["sdelete"])
        self.assertEqual(len(r["journal"]["wipe_events"]), 6)
        self.assertEqual(r["journal"]["wipe_events"][0]["rename_count"], 26)

    def test_eraser_linked_and_not_easttec(self):
        r = self.run_case("R07")
        self.assertEqual(r["stage"], 4)
        self.assertEqual(r["candidate_tools"], ["eraser"])
        self.assertNotIn("easttec", r["presence"])  # eraser.exe 가 eteraser.exe 로 오인되지 않음

    def test_word_save_not_wipe(self):
        self.assertEqual(self.run_case("R08")["alerts"]["journal"], 0)

    def test_missing_prefetch_limits(self):
        r = self.run_case("R09")
        self.assertEqual(r["stage"], 3)
        self.assertTrue(any("Prefetch" in x for x in r["limits"]))

    def test_missing_journal_unknown(self):
        r = self.run_case("R10")
        self.assertEqual(r["stage"], 2)
        self.assertIsNone(r["alerts"]["journal"])
        self.assertIsNone(r["alerts"]["both"])

    def test_exec_missing_with_wipe_is_unknown(self):
        # 저널 패턴은 있으나 Prefetch·레지스트리가 모두 미수집 → 결합 경보는 0이 아니라 판단 불가
        import shutil, tempfile
        tmp = tempfile.mkdtemp()
        try:
            shutil.copytree(os.path.join(self.runs, "R09", "usn"), os.path.join(tmp, "usn"))
            r = wipetrace.analyze(tmp, self.sig)
            self.assertEqual(r["alerts"]["journal"], 1)
            self.assertIsNone(r["alerts"]["exec"])
            self.assertIsNone(r["alerts"]["both"])
            self.assertTrue(any("도구 연계 판단 불가" in x for x in r["limits"]))
        finally:
            shutil.rmtree(tmp)

    def test_parse_failure_is_unknown_not_negative(self):
        # Prefetch CSV를 읽지 못하고 레지스트리 폴더도 없으면 실행 흔적은 0이 아니라 판단 불가
        import shutil, tempfile
        tmp = tempfile.mkdtemp()
        try:
            shutil.copytree(os.path.join(self.runs, "R09", "usn"), os.path.join(tmp, "usn"))
            os.makedirs(os.path.join(tmp, "prefetch"))
            with open(os.path.join(tmp, "prefetch", "bad.csv"), "wb") as f:
                f.write(b"\xff\xfe\xff\x00broken")
            os.makedirs(os.path.join(tmp, "registry"))  # 폴더만 있고 CSV 없음
            r = wipetrace.analyze(tmp, self.sig)
            self.assertEqual(r["data_quality"]["prefetch"]["status"], "파싱실패")
            self.assertEqual(r["data_quality"]["registry"]["status"], "미수집")
            self.assertIsNone(r["alerts"]["exec"])
            self.assertIsNone(r["alerts"]["both"])
        finally:
            shutil.rmtree(tmp)

    def test_evaluate_counts_missing_result_as_unknown(self):
        import csv as _csv
        sys.path.insert(0, os.path.dirname(HERE))
        import evaluate
        res = evaluate.load(os.path.join(HERE, "results_synthetic.csv"))
        ans = evaluate.load(os.path.join(HERE, "answers_synthetic.csv"))
        pos = [c for c in ans if ans[c]["scenario"].upper() == "S4"]
        res.pop(pos[0])
        ev = evaluate.evaluate(res, ans)
        n_pos = len(pos)
        for mode in ("exec", "journal", "both"):
            m = ev["modes"][mode]
            self.assertEqual(m.get("TP", 0) + m.get("FN", 0) + m.get("U+", 0), n_pos)
        self.assertIn(pos[0], ev["missing_results"])

    def test_time_only_link(self):
        # 이름 규칙이 없는 도구는 시간 근접만으로 연계되고 그 사실이 표시된다
        import copy
        sig = copy.deepcopy(self.sig)
        for t in sig["tools"]:
            if t["id"] == "bleachbit":
                t["name_rules"] = []
        r = wipetrace.analyze(os.path.join(self.runs, "R11"), sig)
        self.assertEqual(r["stage"], 4)
        self.assertEqual(r["journal"]["wipe_events"][0]["link_basis"], "시간 근접만(도구 이름 규칙 없음)")

    def test_bleachbit_rule_link(self):
        r = self.run_case("R11")
        self.assertEqual(r["stage"], 4)
        self.assertEqual(r["candidate_tools"], ["bleachbit"])
        self.assertEqual(r["journal"]["wipe_events"][0]["link_basis"], "시간 근접 + 이름 변경 규칙 일치")

    # ---- 작성용 실행(R16~R20)에서 관찰한 이름으로 도구별 규칙을 확인 ----
    OBSERVED = {
        "eraser": ("EVIDENCE_1.bin", ["JI 7i~~1ADFI~6", "mjVhLws'eQmGr4", "nejq9JwQ)iX9rT", "]2kskfLD}Gou!3",
                                      "`[sFcRphquCiG,", "EWBIkM]A=,cMA)", "Uzh6k=ynX5P}ej"]),
        "easttec": ("EVIDENCE_2.bin", ["ELNSDGFHGU.ZAK", "TQKCIFCJFM.SBW", "BMXWJKETGN.MDG", "TENSYQBKHV.LMY"]),
        "sdelete": ("EVIDENCE_1.bin", [c * 10 + "." + c * 3 for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]),
        "bleachbit": ("EVIDENCE_1.bin", ["7xx#6-]w!h~1!_"]),
        "moo0": ("EVIDENCE_1.bin", ["GF5yCvLeKW.BQn", "wNpiWvxIIj.vYy"]),
    }

    def _matching_tools(self, original, names):
        return [t["id"] for t in self.sig["tools"]
                if t["name_rules"] and any(wipetrace._name_rule_match(rule, original, names) for rule in t["name_rules"])]

    def test_observed_names_match_only_own_tool(self):
        for tool, (original, names) in self.OBSERVED.items():
            self.assertEqual(self._matching_tools(original, names), [tool], tool)

    def _journal(self, rows):
        dq = {"inputs": {"usn": {"rows": [("j.csv", i + 2, r) for i, r in enumerate(rows)]}}}
        return wipetrace.find_journal(None, self.sig, dq)

    @staticmethod
    def _row(usn, t, name, reasons, parent=r".\Evidence"):
        return {"EntryNumber": "45", "SequenceNumber": "1", "UpdateSequenceNumber": str(usn), "UpdateTimestamp": t,
                "Name": name, "ParentPath": parent, "UpdateReasons": reasons}

    def test_pending_delete_move_is_delete_moment(self):
        # R18(SDelete): 이름 변경 뒤 $Extend\$Deleted 로 옮겨지고 FileDelete는 한참 뒤(여기서는 10분 뒤)에 기록된다.
        # 이동 시각을 삭제 시점으로 보고, 시스템이 붙인 16진수 이름은 이름 변경으로 세지 않는다.
        rows, usn = [], 100
        rows.append(self._row(usn, "2026-10-05 12:42:38.8140000", "EVIDENCE_1.bin", "DataOverwrite|Close"))
        cur = "EVIDENCE_1.bin"
        for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            n = c * 10 + "." + c * 3
            usn += 10; rows.append(self._row(usn, "2026-10-05 12:42:38.8190000", cur, "RenameOldName"))
            usn += 10; rows.append(self._row(usn, "2026-10-05 12:42:38.8190000", n, "RenameNewName|Close"))
            cur = n
        hexname = "000100000000002D1AEBCD8F"
        usn += 10; rows.append(self._row(usn, "2026-10-05 12:42:38.8240000", cur, "RenameOldName"))
        usn += 10; rows.append(self._row(usn, "2026-10-05 12:42:38.8240000", hexname, "RenameNewName", parent=r".\$Extend\$Deleted"))
        usn += 10; rows.append(self._row(usn, "2026-10-05 12:52:38.0000000", hexname, "FileDelete|RenameNewName|Close", parent=r".\$Extend\$Deleted"))
        ev = self._journal(rows)[0]
        self.assertTrue(ev["pending_delete"])
        self.assertEqual(ev["rename_count"], 26)
        self.assertTrue(ev["is_wipe_pattern"])           # 10분 뒤의 FileDelete가 아니라 이동 시각 기준
        self.assertLess(ev["span_sec"], 1)
        self.assertEqual(ev["delete_ts"][:19], "2026-10-05 12:42:38")
        self.assertEqual(ev["pattern_tools"], ["sdelete"])

    def test_pending_delete_without_tool_rename_not_wipe(self):
        # 열려 있던 파일을 그냥 지운 경우: 덮어쓰기 기록이 있어도 도구의 이름 변경이 없으면 패턴이 아니다
        hexname = "000100000000002D1AEBCD8F"
        rows = [self._row(100, "2026-10-05 12:00:00.0000000", "report.docx", "DataOverwrite|Close"),
                self._row(110, "2026-10-05 12:00:05.0000000", "report.docx", "RenameOldName"),
                self._row(120, "2026-10-05 12:00:05.0000000", hexname, "RenameNewName", parent=r".\$Extend\$Deleted"),
                self._row(130, "2026-10-05 12:00:09.0000000", hexname, "FileDelete|RenameNewName|Close", parent=r".\$Extend\$Deleted")]
        ev = self._journal(rows)[0]
        self.assertEqual(ev["rename_count"], 0)
        self.assertFalse(ev["is_wipe_pattern"])

    def test_hex_name_in_normal_folder_is_not_pending(self):
        # 일반 폴더에서 24자리 16진수 이름으로 바뀐 것은 삭제 대기가 아니다(경로를 읽었으면 경로로만 판단).
        hexname = "0123456789abcdef01234567"
        rows = [self._row(100, "2026-10-05 12:00:00.0000000", "report.docx", "DataOverwrite|Close"),
                self._row(110, "2026-10-05 12:00:05.0000000", "report.docx", "RenameOldName"),
                self._row(120, "2026-10-05 12:00:05.0000000", hexname, "RenameNewName|Close"),
                self._row(130, "2026-10-05 12:00:09.0000000", hexname, "FileDelete|Close")]
        ev = self._journal(rows)[0]
        self.assertFalse(ev["pending_delete"])
        self.assertEqual(ev["rename_count"], 1)
        self.assertEqual(ev["delete_ts"][:19], "2026-10-05 12:00:09")
        self.assertEqual(ev["original_name"], "report.docx")

    def test_hex_name_with_empty_parent_is_pending_by_name(self):
        # 경로가 비어 있으면 이름(24자리 16진수)으로 삭제 대기를 추정하고, 그 이름은 횟수에서 뺀다.
        hexname = "000100000000002D1AEBCD8F"
        rows = [self._row(100, "2026-10-05 12:00:00.0000000", "EVIDENCE_1.bin", "DataOverwrite|Close", parent=""),
                self._row(110, "2026-10-05 12:00:01.0000000", "EVIDENCE_1.bin", "RenameOldName", parent=""),
                self._row(120, "2026-10-05 12:00:01.0000000", "AAAAAAAAAA.AAA", "RenameNewName|Close", parent=""),
                self._row(130, "2026-10-05 12:00:02.0000000", "AAAAAAAAAA.AAA", "RenameOldName", parent=""),
                self._row(140, "2026-10-05 12:00:02.0000000", hexname, "RenameNewName", parent="  "),
                self._row(150, "2026-10-05 12:10:00.0000000", hexname, "FileDelete|RenameNewName|Close", parent="")]
        ev = self._journal(rows)[0]
        self.assertTrue(ev["pending_delete"])
        self.assertEqual(ev["rename_count"], 1)
        self.assertEqual(ev["delete_ts"][:19], "2026-10-05 12:00:02")
        self.assertTrue(ev["is_wipe_pattern"])

    def test_pending_folder_decides_even_if_name_not_hex(self):
        # 삭제 대기 폴더 경로가 있으면 붙은 이름의 모양과 관계없이 이동 시각을 삭제 시점으로 본다.
        rows = [self._row(100, "2026-10-05 12:00:00.0000000", "EVIDENCE_1.bin", "DataOverwrite|Close"),
                self._row(110, "2026-10-05 12:00:01.0000000", "EVIDENCE_1.bin", "RenameOldName"),
                self._row(120, "2026-10-05 12:00:01.0000000", "AAAAAAAAAA.AAA", "RenameNewName|Close"),
                self._row(130, "2026-10-05 12:00:02.0000000", "AAAAAAAAAA.AAA", "RenameOldName"),
                self._row(140, "2026-10-05 12:00:02.0000000", "system-given-name", "RenameNewName", parent=r".\$Extend\$Deleted"),
                self._row(150, "2026-10-05 12:10:00.0000000", "system-given-name", "FileDelete|RenameNewName|Close", parent=r".\$Extend\$Deleted")]
        ev = self._journal(rows)[0]
        self.assertTrue(ev["pending_delete"])
        self.assertEqual(ev["rename_count"], 1)
        self.assertEqual(ev["delete_ts"][:19], "2026-10-05 12:00:02")

    def test_easttec_userassist_not_eraser(self):
        import csv, shutil, tempfile
        d = tempfile.mkdtemp(); os.makedirs(os.path.join(d, "registry"))
        with open(os.path.join(d, "registry", "r.csv"), "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f); w.writerow(["Description", "KeyPath", "ValueName", "ValueData3"])
            w.writerow(["UserAssist", "ROOT\\UserAssist\\Count", "C:\\Program Files\\East-Tec Eraser\\eteraser.exe", "Last executed: 2026-10-01 03:00:00"])
        r = wipetrace.analyze(d, self.sig); shutil.rmtree(d)
        self.assertIn("easttec", r["execution"]); self.assertNotIn("eraser", r["execution"])

    def test_both_subset_of_journal(self):
        for c in sorted(os.listdir(self.runs)):
            a = self.run_case(c)["alerts"]
            if a["both"]:
                self.assertEqual(a["journal"], 1, c)

    def test_rename_truncate_delete_not_wipe(self):
        # R12: 이름 변경 → 절단 → 삭제. 절단은 덮어쓰기가 아니므로 삭제 의심 패턴이 아니어야 함
        r = self.run_case("R12")
        self.assertEqual(r["alerts"]["journal"], 0)
        self.assertTrue(all(not e["is_wipe_pattern"] for e in r["journal"]["wipe_events"]))

    def test_truncate_rename_delete_not_wipe(self):
        # R15: 절단 → 이름 변경 → 삭제 (R12와 순서만 다름)
        r = self.run_case("R15")
        self.assertEqual(r["alerts"]["journal"], 0)

    def test_truncate_delete_not_wipe(self):
        self.assertEqual(self.run_case("R13")["alerts"]["journal"], 0)

    def test_overwrite_without_truncation_is_wipe(self):
        r = self.run_case("R14")
        self.assertEqual(r["alerts"]["journal"], 1)
        ev = r["journal"]["wipe_events"][0]
        self.assertTrue(ev["data_overwrite"]); self.assertFalse(ev["data_truncation"])

    def test_truncation_switch(self):
        # 설정을 켰을 때만 절단이 덮어쓰기 요건을 채움 (1회차 관찰 후 결정용 스위치)
        import copy
        sig = copy.deepcopy(self.sig); sig["rules"]["truncation_counts_as_overwrite"] = True
        r = wipetrace.analyze(os.path.join(self.runs, "R12"), sig)
        self.assertEqual(r["alerts"]["journal"], 1)

    def test_event_reports_both_flags(self):
        ev = self.run_case("R06")["journal"]["wipe_events"][0]
        self.assertTrue(ev["data_overwrite"]); self.assertTrue(ev["data_truncation"])
        self.assertNotIn("overwrite_or_truncate", ev)


if __name__ == "__main__":
    unittest.main()
