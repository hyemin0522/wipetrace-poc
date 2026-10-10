#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
합성 테스트 자료 생성기 - PoC 코드가 의도대로 동작하는지 확인하기 위한 '가짜' EZ Tools CSV.
※ 실험 결과가 아니다. 열 이름만 PECmd/RECmd/AmcacheParser/MFTECmd 출력 형식을 따른다.
   실제 실험 CSV로 돌렸을 때 열 이름이 다르면 wipetrace.py의 읽기 부분을 맞춘다.
"""
import csv
import datetime as dt
import os
import random
import shutil
import string

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "synthetic_runs")
T0 = dt.datetime(2026, 10, 1, 3, 0, 0)

PF_COLS = ["SourceFilename", "ExecutableName", "Hash", "RunCount", "LastRun"] + [f"PreviousRun{i}" for i in range(7)]
REG_COLS = ["HivePath", "HiveType", "Description", "Category", "KeyPath", "ValueName", "ValueType",
            "ValueData", "ValueData2", "ValueData3", "Comment", "Recursive", "Deleted", "LastWriteTimestamp", "PluginDetailFile"]
AM_COLS = ["ProgramName", "SHA1", "FullPath", "FileExtension", "FileKeyLastWriteTimestamp"]
USN_COLS = ["Name", "Extension", "EntryNumber", "SequenceNumber", "ParentEntryNumber", "ParentSequenceNumber",
            "ParentPath", "UpdateSequenceNumber", "UpdateTimestamp", "UpdateReasons", "FileAttributes", "OffsetToData", "SourceFile"]


def ts(t):
    return t.strftime("%Y-%m-%d %H:%M:%S.%f") + "0"


def write(case, sub, name, cols, rows):
    d = os.path.join(OUT, case, sub)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})


class Usn:
    def __init__(self):
        self.rows, self.usn = [], 1000

    def add(self, name, entry, seq, reasons, t, parent=".\\Evidence"):
        self.usn += 96
        self.rows.append({"Name": name, "Extension": os.path.splitext(name)[1], "EntryNumber": entry,
                          "SequenceNumber": seq, "ParentEntryNumber": 40, "ParentSequenceNumber": 1,
                          "ParentPath": parent, "UpdateSequenceNumber": self.usn, "UpdateTimestamp": ts(t),
                          "UpdateReasons": reasons, "FileAttributes": "Archive", "OffsetToData": 0, "SourceFile": "D_$J"})

    def create(self, name, entry, t):
        self.add(name, entry, 2, "FileCreate", t)
        self.add(name, entry, 2, "DataExtend|FileCreate", t)
        self.add(name, entry, 2, "DataExtend|FileCreate|Close", t)

    def wipe(self, name, entry, t, new_names, truncate=True, overwrite=True, truncate_first=False):
        if truncate_first:
            self.add(name, entry, 2, "DataTruncation", t)
        if overwrite:
            self.add(name, entry, 2, "DataOverwrite", t)
            self.add(name, entry, 2, "DataOverwrite|Close", t + dt.timedelta(seconds=1))
        cur = name
        for i, n in enumerate(new_names):
            tt = t + dt.timedelta(seconds=2 + i)
            self.add(cur, entry, 2, "RenameOldName", tt)
            self.add(n, entry, 2, "RenameNewName", tt)
            self.add(n, entry, 2, "RenameNewName|Close", tt)
            cur = n
        tt = t + dt.timedelta(seconds=3 + len(new_names))
        if truncate and not truncate_first:
            self.add(cur, entry, 2, "DataTruncation", tt)
        self.add(cur, entry, 2, "FileDelete|Close", tt)


def files(u, t=T0):
    names = [f"EVIDENCE_{i}.bin" for i in range(1, 7)]
    for i, n in enumerate(names):
        u.create(n, 100 + i, t)
    return names


def pf(exe, run):
    return {"SourceFilename": f"C:\\Windows\\Prefetch\\{exe}-1A2B3C4D.pf", "ExecutableName": exe,
            "Hash": "1A2B3C4D", "RunCount": 1, "LastRun": ts(run)}


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    answers = []
    rnd = random.Random(7)

    def done(case, scen, tool, use="적용"):
        answers.append({"case": case, "scenario": scen, "tool": tool, "use": use})

    # S0 기준선: 파일 생성만
    u = Usn(); files(u); write("R01", "usn", "D_$J_Output.csv", USN_COLS, u.rows)
    write("R01", "prefetch", "pf.csv", PF_COLS, [pf("NOTEPAD.EXE", T0)])
    write("R01", "registry", "reg.csv", REG_COLS, []); write("R01", "amcache", "am.csv", AM_COLS, [])
    done("R01", "S0", "")

    # S1 Eraser 설치만: Amcache·Uninstall 키, 설치 프로그램 Prefetch만
    u = Usn(); files(u); write("R02", "usn", "j.csv", USN_COLS, u.rows)
    write("R02", "prefetch", "pf.csv", PF_COLS, [pf("ERASER 6.2.0.2996.EXE", T0 + dt.timedelta(minutes=2))])
    write("R02", "amcache", "am.csv", AM_COLS, [{"ProgramName": "Eraser 6.2.0.2996", "FullPath": "c:\\program files\\eraser\\eraser.exe"}])
    write("R02", "registry", "reg.csv", REG_COLS, [{"Description": "Installed software", "Category": "Installed software",
          "KeyPath": "ROOT\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{Eraser}", "ValueName": "DisplayName", "ValueData": "Eraser 6.2.0.2996"}])
    done("R02", "S1", "eraser")

    # S2 SDelete 실행만(도움말만 보고 종료)
    u = Usn(); files(u); write("R03", "usn", "j.csv", USN_COLS, u.rows)
    write("R03", "prefetch", "pf.csv", PF_COLS, [pf("SDELETE64.EXE", T0 + dt.timedelta(minutes=5))])
    write("R03", "registry", "reg.csv", REG_COLS, [{"Description": "Sysinternals", "KeyPath": "ROOT\\Software\\Sysinternals\\SDelete", "ValueName": "EulaAccepted", "ValueData": "1"}])
    write("R03", "amcache", "am.csv", AM_COLS, [])
    done("R03", "S2", "sdelete")

    # S3 일반 삭제(Shift+Delete)
    u = Usn(); names = files(u)
    for i, n in enumerate(names):
        u.add(n, 100 + i, 2, "FileDelete|Close", T0 + dt.timedelta(minutes=5))
    write("R04", "usn", "j.csv", USN_COLS, u.rows); write("R04", "prefetch", "pf.csv", PF_COLS, [])
    write("R04", "registry", "reg.csv", REG_COLS, []); write("R04", "amcache", "am.csv", AM_COLS, [])
    done("R04", "S3", "")

    # S3 변형: 휴지통 이동 후 비우기($R 이름 변경) → 완전삭제 패턴 아님
    u = Usn(); names = files(u)
    for i, n in enumerate(names):
        t = T0 + dt.timedelta(minutes=5)
        u.add(n, 100 + i, 2, "RenameOldName", t)
        u.add(f"$R{i}ABC12.bin", 100 + i, 2, "RenameNewName", t, parent=".\\$Recycle.Bin\\S-1-5-21")
        u.add(f"$R{i}ABC12.bin", 100 + i, 2, "FileDelete|Close", t + dt.timedelta(seconds=20), parent=".\\$Recycle.Bin\\S-1-5-21")
    write("R05", "usn", "j.csv", USN_COLS, u.rows); write("R05", "prefetch", "pf.csv", PF_COLS, [])
    write("R05", "registry", "reg.csv", REG_COLS, []); write("R05", "amcache", "am.csv", AM_COLS, [])
    done("R05", "S3", "")

    # S4 SDelete: AAA.AAA … 반복 문자 이름
    u = Usn(); names = files(u); t = T0 + dt.timedelta(minutes=6)
    for i, n in enumerate(names):
        stem, ext = os.path.splitext(n)
        seq = [c * len(stem) + "." + c * (len(ext) - 1) for c in string.ascii_uppercase]
        u.wipe(n, 100 + i, t + dt.timedelta(seconds=40 * i), seq)
    write("R06", "usn", "j.csv", USN_COLS, u.rows)
    write("R06", "prefetch", "pf.csv", PF_COLS, [pf("SDELETE64.EXE", T0 + dt.timedelta(minutes=5, seconds=50))])
    write("R06", "registry", "reg.csv", REG_COLS, []); write("R06", "amcache", "am.csv", AM_COLS, [])
    done("R06", "S4", "sdelete")

    # S4 Eraser: 같은 길이 무작위 이름
    u = Usn(); names = files(u); t = T0 + dt.timedelta(minutes=9)
    for i, n in enumerate(names):
        seq = ["".join(rnd.choice(string.ascii_letters + string.digits) for _ in n) for _ in range(7)]
        u.wipe(n, 100 + i, t + dt.timedelta(seconds=15 * i), seq)
    write("R07", "usn", "j.csv", USN_COLS, u.rows)
    write("R07", "prefetch", "pf.csv", PF_COLS, [pf("ERASER.EXE", T0 + dt.timedelta(minutes=7))])
    write("R07", "registry", "reg.csv", REG_COLS, [{"Description": "UserAssist", "Category": "Program Execution",
          "KeyPath": "ROOT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD}\\Count",
          "ValueName": "{6D809377-6AF0-444B-8957-A3773F02200E}\\Eraser\\Eraser.exe", "ValueData": "Eraser.exe",
          "ValueData2": "Run count: 1", "ValueData3": "Last executed: " + ts(T0 + dt.timedelta(minutes=7))}])
    write("R07", "amcache", "am.csv", AM_COLS, [{"FullPath": "c:\\program files\\eraser\\eraser.exe"}])
    done("R07", "S4", "eraser")

    # 정상 편집(Word식 저장): 이름 변경 후 삭제, 덮어쓰기 없음 → 패턴 아님
    u = Usn(); names = files(u); t = T0 + dt.timedelta(minutes=4)
    u.add(names[0], 100, 2, "RenameOldName", t); u.add("~WRL0001.tmp", 100, 2, "RenameNewName", t)
    u.add("~WRL0001.tmp", 100, 2, "FileDelete|Close", t + dt.timedelta(seconds=3))
    write("R08", "usn", "j.csv", USN_COLS, u.rows); write("R08", "prefetch", "pf.csv", PF_COLS, [pf("WINWORD.EXE", t)])
    write("R08", "registry", "reg.csv", REG_COLS, []); write("R08", "amcache", "am.csv", AM_COLS, [])
    done("R08", "S0", "")

    # S4 Eraser인데 Prefetch 미수집 → 3단계 + 판단 제한
    u = Usn(); names = files(u); t = T0 + dt.timedelta(minutes=9)
    for i, n in enumerate(names):
        u.wipe(n, 100 + i, t, ["".join(rnd.choice(string.ascii_letters) for _ in n) for _ in range(7)])
    write("R09", "usn", "j.csv", USN_COLS, u.rows); write("R09", "registry", "reg.csv", REG_COLS, [])
    write("R09", "amcache", "am.csv", AM_COLS, [])
    done("R09", "S4", "eraser")

    # S4 SDelete인데 저널 미수집 → 2단계 + 판단 제한(journal/both 판단 불가)
    write("R10", "prefetch", "pf.csv", PF_COLS, [pf("SDELETE64.EXE", T0)])
    write("R10", "registry", "reg.csv", REG_COLS, []); write("R10", "amcache", "am.csv", AM_COLS, [])
    done("R10", "S4", "sdelete")

    # S4 BleachBit: 같은 길이의 소문자·숫자 이름으로 1회 변경(R19 관찰)
    u = Usn(); names = files(u); t = T0 + dt.timedelta(minutes=12)
    for i, n in enumerate(names):
        u.wipe(n, 100 + i, t, ["".join(rnd.choice(string.ascii_lowercase + string.digits) for _ in n)])
    write("R11", "usn", "j.csv", USN_COLS, u.rows); write("R11", "prefetch", "pf.csv", PF_COLS, [pf("BLEACHBIT.EXE", T0 + dt.timedelta(minutes=10))])
    write("R11", "registry", "reg.csv", REG_COLS, []); write("R11", "amcache", "am.csv", AM_COLS, [])
    done("R11", "S4", "bleachbit")

    # 음성: 이름 변경 → 크기 절단 → 삭제 (덮어쓰기 없음). 예) 이름을 바꾼 뒤 비우고 지우는 정상 프로그램
    u = Usn(); names = files(u); t = T0 + dt.timedelta(minutes=4)
    for i, n in enumerate(names[:2]):
        u.wipe(n, 100 + i, t, [f"~tmp{i}.del"], truncate=True, overwrite=False)
    write("R12", "usn", "j.csv", USN_COLS, u.rows); write("R12", "prefetch", "pf.csv", PF_COLS, [pf("SETUPHOST.EXE", t)])
    write("R12", "registry", "reg.csv", REG_COLS, []); write("R12", "amcache", "am.csv", AM_COLS, [])
    done("R12", "S0", "")

    # 음성: 크기 절단 → 삭제 (이름 변경·덮어쓰기 없음)
    u = Usn(); names = files(u); t = T0 + dt.timedelta(minutes=4)
    for i, n in enumerate(names[:2]):
        u.add(n, 100 + i, 2, "DataTruncation", t); u.add(n, 100 + i, 2, "FileDelete|Close", t + dt.timedelta(seconds=1))
    write("R13", "usn", "j.csv", USN_COLS, u.rows); write("R13", "prefetch", "pf.csv", PF_COLS, [])
    write("R13", "registry", "reg.csv", REG_COLS, []); write("R13", "amcache", "am.csv", AM_COLS, [])
    done("R13", "S0", "")

    # 양성: 덮어쓰기 → 이름 변경 → 삭제 (절단 없음) — 절단이 없어도 탐지돼야 함
    u = Usn(); names = files(u); t = T0 + dt.timedelta(minutes=12)
    for i, n in enumerate(names):
        u.wipe(n, 100 + i, t, ["".join(rnd.choice(string.ascii_lowercase + string.digits) for _ in n)], truncate=False)
    write("R14", "usn", "j.csv", USN_COLS, u.rows); write("R14", "prefetch", "pf.csv", PF_COLS, [pf("BLEACHBIT.EXE", T0 + dt.timedelta(minutes=10))])
    write("R14", "registry", "reg.csv", REG_COLS, []); write("R14", "amcache", "am.csv", AM_COLS, [])
    done("R14", "S4", "bleachbit")

    # 음성: 크기 절단 → 이름 변경 → 삭제 (덮어쓰기 없음). R12와 순서만 다름
    u = Usn(); names = files(u); t = T0 + dt.timedelta(minutes=4)
    for i, n in enumerate(names[:2]):
        u.wipe(n, 100 + i, t, [f"~tmp{i}.del"], truncate=True, overwrite=False, truncate_first=True)
    write("R15", "usn", "j.csv", USN_COLS, u.rows); write("R15", "prefetch", "pf.csv", PF_COLS, [pf("SETUPHOST.EXE", t)])
    write("R15", "registry", "reg.csv", REG_COLS, []); write("R15", "amcache", "am.csv", AM_COLS, [])
    done("R15", "S0", "")

    with open(os.path.join(OUT, "..", "answers_synthetic.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["case", "scenario", "tool", "use"])
        w.writeheader(); w.writerows(answers)
    print(f"합성 실행 {len(answers)}개 생성: {OUT}")


if __name__ == "__main__":
    main()
