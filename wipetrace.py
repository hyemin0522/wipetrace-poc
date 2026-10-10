#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wipetrace.py - 완전삭제 도구 사용 흔적 판별 PoC

입력  : EZ Tools(PECmd, RECmd, AmcacheParser, MFTECmd)가 만든 CSV + 도구 시그니처(YAML/JSON)
처리  : 존재(P) / 실행(E) / 저널 삭제 패턴(J) / 도구 연계(L) 근거를 따로 추출
출력  : 판별 단계(0~4), 모드별 경보(exec / journal / both), 근거 행 위치가 달린 보고서

사용 예
  python wipetrace.py analyze  CASE_DIR  --sig signatures.yaml --out report_dir
  python wipetrace.py batch    RUNS_DIR  --sig signatures.yaml --out results.csv
  python wipetrace.py freeze   --sig signatures.yaml            (규칙 고정용 SHA-256 기록)

CASE_DIR 구성 (없는 폴더는 '미수집'으로 표시)
  prefetch/  PECmd CSV (본 출력 또는 _Timeline.csv)
  registry/  RECmd CSV (Kroll 배치 등)
  amcache/   AmcacheParser CSV
  mft/       MFTECmd $MFT CSV (선택)
  usn/       MFTECmd $J CSV

주의: 정답(시나리오·도구명)은 입력에 넣지 않는다. 정답 대조는 evaluate.py가 한다.
"""
import argparse
import csv
import datetime as dt
import glob
import hashlib
import json
import os
import re
import sys
from collections import defaultdict

__version__ = "0.5.1"

STAGE_TEXT = {
    0: "흔적 없음",
    1: "존재 흔적",
    2: "실행 흔적",
    3: "삭제 행위 의심(저널 패턴)",
    4: "도구 연계 정황",
}

# --------------------------------------------------------------------------- 공통 유틸

TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?")


def parse_ts(text):
    """문자열 안의 첫 'YYYY-MM-DD HH:MM:SS(.fffffff)'를 datetime(UTC 가정)으로 바꾼다."""
    if not text:
        return None
    m = TS_RE.search(str(text))
    if not m:
        return None
    frac = (m.group(3) or "0")[:6].ljust(6, "0")
    try:
        return dt.datetime.strptime(f"{m.group(1)} {m.group(2)}.{frac}", "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        return None


def all_ts(values):
    out = []
    for v in values:
        for m in TS_RE.finditer(str(v or "")):
            t = parse_ts(m.group(0))
            if t:
                out.append(t)
    return out


def fmt(t):
    return t.strftime("%Y-%m-%d %H:%M:%S") if t else ""


def read_csvs(folder, pattern="*.csv"):
    """폴더의 CSV를 모두 읽어 (파일명, 행번호, dict) 목록을 돌려준다. 행번호는 헤더 포함 1부터."""
    rows, files, errors = [], [], []
    if not os.path.isdir(folder):
        return None, files, errors
    for path in sorted(glob.glob(os.path.join(folder, pattern))):
        files.append(os.path.basename(path))
        try:
            with open(path, encoding="utf-8-sig", newline="") as f:
                for i, r in enumerate(csv.DictReader(f), start=2):
                    rows.append((os.path.basename(path), i, r))
        except Exception as e:  # 파싱 실패는 결과에 남긴다
            errors.append(f"{os.path.basename(path)}: {e}")
    return rows, files, errors


def load_signatures(path):
    with open(path, encoding="utf-8") as f:
        if path.lower().endswith(".json"):
            sig = json.load(f)
        else:
            try:
                import yaml
            except ImportError:
                sys.exit("PyYAML이 필요합니다: pip install pyyaml  (또는 JSON 시그니처 사용)")
            sig = yaml.safe_load(f)
    rules = {"link_window_min": 30, "link_slack_min": 2, "burst_window_sec": 300,
             "min_renames": 1, "require_overwrite": True, "truncation_counts_as_overwrite": False,
             "ignore_path_keywords": ["$Recycle.Bin"], "ignore_name_regex": [r"^\$R[A-Z0-9]{6}"],
             "ignore_env_path_keywords": [],
             "pending_delete_path_keywords": [r"$Extend\$Deleted"],
             "pending_delete_name_regex": r"^[0-9A-Fa-f]{24}$"}
    rules.update(sig.get("rules", {}))
    sig["rules"] = rules
    for t in sig.get("tools", []):
        t["executables_u"] = [x.upper() for x in t.get("executables", [])]
        pres = t.get("presence", {})
        t["keywords_l"] = [k.lower() for k in pres.get("keywords", [])]
        t["name_rules"] = t.get("journal", {}).get("name_rules", [])
    return sig


# --------------------------------------------------------------------------- 1) 존재 흔적 P

def find_presence(case, sig, dq):
    """Amcache·레지스트리·(선택)MFT의 모든 문자열 칸에서 도구 키워드를 찾는다.
    Amcache는 설계상 '존재·식별 보조'로만 쓴다(실행 근거로 쓰지 않음)."""
    found = defaultdict(list)
    sources = {"amcache": "amcache", "registry": "registry", "mft": "mft"}
    # 실험 환경에서 생긴 경로(예: 설치 파일을 두는 VM 공유 폴더)는 존재 근거에서 뺀다
    skip = [k.lower() for k in sig["rules"].get("ignore_env_path_keywords", []) if k]
    for key, sub in sources.items():
        rows = dq["inputs"][key]["rows"]
        if rows is None:
            continue
        for fname, line, r in rows:
            blob = " | ".join(str(v) for v in r.values() if v).lower()
            if key == "mft" and str(r.get("InUse", "True")).lower() in ("false", "0"):
                continue  # 삭제된 엔트리는 존재 근거에서 제외
            if any(k in blob for k in skip):
                continue
            for t in sig["tools"]:
                hit = [k for k in t["keywords_l"] if k and k in blob]
                # 실행 파일명은 앞이 경로 구분자·공백일 때만 일치(eraser.exe ≠ eteraser.exe)
                hit += [e.lower() for e in t["executables_u"]
                        if re.search(r"(?:^|[\\/\s|\"'])" + re.escape(e.lower()), blob)]
                if hit:
                    desc = r.get("Description") or r.get("Category") or r.get("ProgramName") or r.get("FullPath") \
                        or (r.get("ParentPath", "") + "\\" + r.get("FileName", ""))
                    found[t["id"]].append({"source": key, "file": fname, "row": line,
                                           "keyword": hit[0], "detail": str(desc)[:160]})
    return found


# --------------------------------------------------------------------------- 2) 실행 흔적 E

EXEC_REG_HINTS = ("userassist", "bam", "dam", "muicache")


def find_execution(case, sig, dq):
    found = defaultdict(list)
    # (a) Prefetch - PECmd 본 출력(LastRun, PreviousRun0..6) 또는 Timeline(RunTime)
    rows = dq["inputs"]["prefetch"]["rows"]
    if rows is not None:
        for fname, line, r in rows:
            exe = (r.get("ExecutableName") or "").upper()
            exe_base = exe.split("\\")[-1]
            for t in sig["tools"]:
                if exe_base and any(exe_base == e or (len(exe_base) >= 29 and e.startswith(exe_base)) for e in t["executables_u"]):
                    if "RunTime" in r:
                        times = all_ts([r.get("RunTime")])
                    else:
                        times = all_ts([r.get("LastRun")] + [r.get(f"PreviousRun{i}") for i in range(7)])
                    found[t["id"]].append({"source": "prefetch", "file": fname, "row": line,
                                           "exe": exe_base, "run_count": r.get("RunCount", ""),
                                           "times": sorted(set(times))})
    # (b) 레지스트리 - UserAssist, BAM/DAM, MUICache 행(Description/Category/KeyPath로 구분)
    rows = dq["inputs"]["registry"]["rows"]
    skip = [k.upper() for k in sig["rules"].get("ignore_env_path_keywords", []) if k]
    if rows is not None:
        for fname, line, r in rows:
            kind_blob =" ".join(str(r.get(k, "")) for k in ("Description", "Category", "KeyPath", "PluginDetailFile")).lower()
            kind = next((h for h in EXEC_REG_HINTS if h in kind_blob), None)
            if not kind:
                continue
            val_blob = " ".join(str(r.get(k, "")) for k in ("ValueName", "ValueData", "ValueData2", "ValueData3", "KeyPath")).upper()
            if any(k in val_blob for k in skip):
                continue  # 실험 환경 경로(공유 폴더)에서 실행한 설치 파일은 도구 실행으로 세지 않는다
            for t in sig["tools"]:
                # 경로 구분자·공백 뒤에서만 일치(ERASER.EXE ≠ ETERASER.EXE)
                exe = next((e for e in t["executables_u"]
                            if re.search(r"(?:^|[\\/\s|\"'])" + re.escape(e), val_blob)), None)
                if not exe:
                    continue
                times = all_ts([r.get("ValueData"), r.get("ValueData2"), r.get("ValueData3")])
                if kind == "muicache":
                    times = []  # MUICache에는 값별 실행 시각이 없다
                found[t["id"]].append({"source": kind, "file": fname, "row": line, "exe": exe,
                                       "times": sorted(set(times))})
    return found


# --------------------------------------------------------------------------- 3) 저널 삭제 패턴 J

def _reasons(s):
    return set(x.strip() for x in str(s or "").replace(",", "|").split("|") if x.strip())


def _name_rule_match(rule, original, new_names):
    """도구별 이름 변경 규칙. regex / same_length / repeated_char / extension / charset."""
    typ, val = rule.get("type"), rule.get("value")
    if not new_names:
        return False
    if typ == "regex":
        rx = re.compile(val)
        return sum(1 for n in new_names if rx.search(n)) >= max(1, int(rule.get("min", 1)))
    if typ == "same_length":
        return all(len(n) == len(original) and n != original for n in new_names)
    if typ == "repeated_char":  # 예: AAA.AAA, ZZZZZ
        return all(len(set(n.replace(".", ""))) == 1 for n in new_names)
    if typ == "extension":
        return any(n.lower().endswith("." + str(val).lower()) for n in new_names)
    if typ == "charset":
        # 모든 새 이름이 정해진 글자 집합(정규식 전체 일치)에 들고, 선택 조건(길이·점 위치·글자 종류 수·횟수)을 채워야 한다.
        rx = re.compile(val)
        if not all(rx.fullmatch(n) for n in new_names):
            return False
        if rule.get("same_length") and not all(len(n) == len(original) and n != original for n in new_names):
            return False
        if rule.get("keep_dots") is not None:
            def dots(x):
                return [i for i, c in enumerate(x) if c == "."]
            kept = all(dots(n) == dots(original) for n in new_names)
            if kept != bool(rule["keep_dots"]):
                return False
        if rule.get("min_unique_chars") and not all(len(set(n.replace(".", ""))) >= int(rule["min_unique_chars"]) for n in new_names):
            return False
        if rule.get("min_renames") is not None and len(new_names) < int(rule["min_renames"]):
            return False
        if rule.get("max_renames") is not None and len(new_names) > int(rule["max_renames"]):
            return False
        return True
    return False


def find_journal(case, sig, dq):
    rows = dq["inputs"]["usn"]["rows"]
    if rows is None:
        return None  # 미수집 → 판단 불가
    R = sig["rules"]
    ign_path = [k.lower() for k in R["ignore_path_keywords"]]
    ign_name = [re.compile(x) for x in R["ignore_name_regex"]]
    # 삭제 대기: Windows는 열려 있는 파일을 지울 때 $Extend\$Deleted 로 옮기고 16진수 이름을 붙인 뒤,
    # 마지막 핸들이 닫힐 때(늦으면 시스템 종료 때) FileDelete를 기록한다. 이 이동을 삭제 시점으로 본다.
    pend_path = [k.lower() for k in R.get("pending_delete_path_keywords", []) if k]
    pend_name = re.compile(R["pending_delete_name_regex"]) if R.get("pending_delete_name_regex") else None

    def is_pending(x):
        if "RenameNewName" not in x["reasons"]:
            return False
        parent = (x["parent"] or "").strip()
        if parent:      # 경로를 읽었으면 경로만으로 판단한다(일반 폴더에서 16진수 이름으로 바뀐 것은 삭제 대기가 아님)
            return any(k in parent.lower() for k in pend_path)
        return bool(pend_name and pend_name.fullmatch(x["name"]))   # 경로가 비어 있을 때만 이름으로 추정

    groups = defaultdict(list)
    for fname, line, r in rows:
        try:
            ref = (int(r.get("EntryNumber", -1)), int(r.get("SequenceNumber", -1)))
        except ValueError:
            continue
        usn = int(r.get("UpdateSequenceNumber") or 0)
        groups[ref].append({"usn": usn, "ts": parse_ts(r.get("UpdateTimestamp")), "name": r.get("Name", ""),
                            "parent": r.get("ParentPath", ""), "reasons": _reasons(r.get("UpdateReasons")),
                            "file": fname, "row": line})
    events = []
    for ref, recs in groups.items():
        recs.sort(key=lambda x: x["usn"])  # 저널 내부 순서는 USN 기준
        deletes = [x for x in recs if "FileDelete" in x["reasons"]]
        if not deletes:
            continue
        d = deletes[0]
        before = [x for x in recs if x["usn"] <= d["usn"]]
        old = next((x["name"] for x in before if "RenameOldName" in x["reasons"]), before[0]["name"])
        pending = next((x for x in before if is_pending(x)), None)
        moment = pending or d              # 삭제 시점: 삭제 대기 이동이 있으면 그 시각, 없으면 FileDelete
        if pending:
            before = [x for x in before if x["usn"] < pending["usn"]] or [pending]
        new_names, prev = [], None
        for x in before:
            if "RenameNewName" in x["reasons"] and x["name"] != prev:
                new_names.append(x["name"])
                prev = x["name"]
        # DataOverwrite(기존 데이터 위에 쓰기)와 DataTruncation(크기 줄이기)은 다른 동작이다(MS-FSCC USN_REASON).
        # 절단은 기본적으로 덮어쓰기 요건을 채우지 않는다. 1회차 관찰 후 필요할 때만 설정으로 켠다.
        overwrite = any("DataOverwrite" in x["reasons"] for x in before)
        truncation = any("DataTruncation" in x["reasons"] for x in before)
        overwrite_ok = overwrite or (bool(R.get("truncation_counts_as_overwrite")) and truncation)
        wipe_related = [x for x in before if x["reasons"] & {"DataOverwrite", "DataTruncation", "RenameNewName", "RenameOldName"}]
        first = wipe_related[0]["ts"] if wipe_related else moment["ts"]
        span = (moment["ts"] - first).total_seconds() if (moment["ts"] and first) else None
        parents = " ".join(x["parent"] for x in before).lower()
        recycle = any(k in parents for k in ign_path) or (new_names and all(any(rx.search(n) for rx in ign_name) for n in new_names))
        is_wipe = (not recycle
                   and len(new_names) >= int(R["min_renames"])
                   and (overwrite_ok or not R["require_overwrite"])
                   and span is not None and span <= float(R["burst_window_sec"]))
        matched = []
        for t in sig["tools"]:
            rules = t["name_rules"]
            if rules and any(_name_rule_match(rule, old, new_names) for rule in rules):
                matched.append(t["id"])
        events.append({"file_ref": f"{ref[0]}-{ref[1]}", "original_name": old, "new_names": new_names[:30],
                       "rename_count": len(new_names), "data_overwrite": overwrite, "data_truncation": truncation,
                       "delete_ts": fmt(moment["ts"]), "_delete_dt": moment["ts"], "span_sec": span,
                       "pending_delete": bool(pending), "delete_record_ts": fmt(d["ts"]),
                       "recycle_bin": bool(recycle), "is_wipe_pattern": bool(is_wipe),
                       "pattern_tools": matched, "usn_range": [before[0]["usn"], d["usn"]],
                       "evidence": [f'{d["file"]}:{x["row"]}' for x in before][-40:]})
    return events


# --------------------------------------------------------------------------- 4) 연계 L 과 단계 판정

def link(events, execs, sig):
    R = sig["rules"]
    win = dt.timedelta(minutes=float(R["link_window_min"]))
    slack = dt.timedelta(minutes=float(R["link_slack_min"]))
    tools = {t["id"]: t for t in sig["tools"]}
    for ev in events:
        ev["linked_tools"], ev["time_only_tools"] = [], []
        if not ev["is_wipe_pattern"] or not ev["_delete_dt"]:
            continue
        for tid, hits in execs.items():
            times = [x for h in hits for x in h["times"]]
            ok = any(ev["_delete_dt"] - win <= x <= ev["_delete_dt"] + slack for x in times)
            if not ok:
                continue
            if tools[tid]["name_rules"]:
                if tid in ev["pattern_tools"]:
                    ev["linked_tools"].append(tid)  # 시간 근접 + 도구 이름 규칙 일치
            else:
                ev["time_only_tools"].append(tid)  # 도구 패턴 미정: 시간 근접만 성립
        if not ev["linked_tools"] and ev["time_only_tools"]:
            ev["linked_tools"] = list(ev["time_only_tools"])
            ev["link_basis"] = "시간 근접만(도구 이름 규칙 없음)"
        elif ev["linked_tools"]:
            ev["link_basis"] = "시간 근접 + 이름 변경 규칙 일치"
    return events


def analyze(case, sig):
    dq = {"inputs": {}, "notes": []}
    for key in ("prefetch", "registry", "amcache", "mft", "usn"):
        rows, files, errors = read_csvs(os.path.join(case, key))
        status = "미수집" if rows is None else ("파싱실패" if errors and not rows else ("수집·빈 자료" if not rows else "수집"))
        if rows is not None and not files:
            status = "미수집"  # 폴더만 있고 CSV가 없음
        if status in ("미수집", "파싱실패"):
            rows = None  # 읽지 못한 자료를 '흔적 없음'(음성)으로 바꾸지 않고 판단 불가로 다룬다
        dq["inputs"][key] = {"rows": rows, "files": files, "errors": errors, "status": status}
    presence = find_presence(case, sig, dq)
    execution = find_execution(case, sig, dq)
    events = find_journal(case, sig, dq)
    journal_available = events is not None
    events = link(events or [], execution, sig)
    wipe = [e for e in events if e["is_wipe_pattern"]]
    linked = [e for e in wipe if e.get("linked_tools")]
    E = any(bool(v) for v in execution.values())
    J = bool(wipe)
    stage = 4 if linked else 3 if J else 2 if E else 1 if presence else 0
    limits = []
    if not journal_available:
        limits.append(f"저널($J) {dq['inputs']['usn']['status']}: 삭제 행위 판단 불가")
    if dq["inputs"]["prefetch"]["rows"] is None:
        limits.append(f"Prefetch {dq['inputs']['prefetch']['status']}: 실행 근거가 레지스트리에 한정됨")
    for k, v in dq["inputs"].items():
        if v["errors"]:
            limits.append(f"{k} 파싱 오류 {len(v['errors'])}건")
    cands = sorted({t for e in linked for t in e["linked_tools"]})
    if len(cands) > 1:
        limits.append("복수 후보 도구")
    exec_available = dq["inputs"]["prefetch"]["rows"] is not None or dq["inputs"]["registry"]["rows"] is not None
    # 결합 경보: 저널이 없으면 판단 불가. 저널 패턴이 있는데 실행 자료가 모두 미수집이면 연계를 볼 수 없으므로 판단 불가.
    # 저널이 있고 패턴이 없으면 실행 자료와 관계없이 0(결합 조건 불충족).
    if not journal_available or (J and not exec_available):
        both = None
    else:
        both = int(bool(linked))
    if J and not exec_available:
        limits.append("실행 자료(Prefetch·레지스트리) 미수집: 도구 연계 판단 불가")
    alerts = {"exec": int(E) if exec_available else None, "journal": int(J) if journal_available else None, "both": both}
    for e in events:
        e.pop("_delete_dt", None)
    return {
        "case": os.path.basename(os.path.normpath(case)), "wipetrace_version": __version__,
        "signature_version": sig.get("meta", {}).get("version", ""),
        "stage": stage, "stage_text": STAGE_TEXT[stage], "alerts": alerts,
        "candidate_tools": cands,
        "presence": {k: v[:20] for k, v in presence.items()},
        "execution": {k: [{**h, "times": [fmt(x) for x in h["times"]]} for h in v] for k, v in execution.items()},
        "journal": {"available": journal_available, "wipe_events": wipe,
                    "other_deletes": len(events) - len(wipe)},
        "limits": limits,
        "data_quality": {k: {"status": v["status"], "files": v["files"], "errors": v["errors"]} for k, v in dq["inputs"].items()},
    }


# --------------------------------------------------------------------------- 출력

def write_report(res, outdir):
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2, default=str)
    L = [f"# 판별 결과: {res['case']}", "",
         f"- 판별 단계: **{res['stage']} ({res['stage_text']})**",
         f"- 경보: exec={res['alerts']['exec']}, journal={res['alerts']['journal']}, both={res['alerts']['both']}",
         f"- 연계 후보 도구: {', '.join(res['candidate_tools']) or '-'}",
         f"- 판단 제한: {'; '.join(res['limits']) or '-'}", "", "## 존재 흔적"]
    for t, hits in res["presence"].items():
        for h in hits[:5]:
            L.append(f"- {t}: {h['source']} `{h['file']}` {h['row']}행 ({h['keyword']})")
    L.append("\n## 실행 흔적")
    for t, hits in res["execution"].items():
        for h in hits:
            L.append(f"- {t}: {h['source']} `{h['file']}` {h['row']}행 {h['exe']} 시각={', '.join(h['times'][:8]) or '없음'}")
    L.append("\n## 저널 삭제 패턴")
    if not res["journal"]["available"]:
        L.append("- 저널 미수집")
    for e in res["journal"]["wipe_events"]:
        L.append(f"- 파일참조 {e['file_ref']} `{e['original_name']}` 이름변경 {e['rename_count']}회 "
                 f"(예: {', '.join(e['new_names'][:3])}) 덮어쓰기(DataOverwrite)={'있음' if e['data_overwrite'] else '없음'} 크기 절단(DataTruncation)={'있음' if e['data_truncation'] else '없음'} "
                 f"삭제={e['delete_ts']} USN {e['usn_range'][0]}~{e['usn_range'][1]} "
                 f"→ 연계: {', '.join(e.get('linked_tools', [])) or '없음'} {e.get('link_basis', '')}")
    L.append(f"- 삭제 패턴이 아닌 삭제 레코드 묶음: {res['journal']['other_deletes']}개")
    L.append("\n## 자료 상태")
    for k, v in res["data_quality"].items():
        L.append(f"- {k}: {v['status']} {', '.join(v['files'])}")
    L.append("\n※ 결합 경보 0은 '삭제 없음'이라는 사실 판정이 아니다. 저널에는 프로세스 ID가 없으므로 연계는 정황이다.")
    with open(os.path.join(outdir, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


SUMMARY_FIELDS = ["case", "stage", "stage_text", "alert_exec", "alert_journal", "alert_both",
                  "candidate_tools", "wipe_events", "limits"]


def summary_row(res):
    return {"case": res["case"], "stage": res["stage"], "stage_text": res["stage_text"],
            "alert_exec": "" if res["alerts"]["exec"] is None else res["alerts"]["exec"],
            "alert_journal": "" if res["alerts"]["journal"] is None else res["alerts"]["journal"],
            "alert_both": "" if res["alerts"]["both"] is None else res["alerts"]["both"],
            "candidate_tools": ";".join(res["candidate_tools"]),
            "wipe_events": len(res["journal"]["wipe_events"]), "limits": "; ".join(res["limits"])}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description="완전삭제 도구 사용 흔적 판별 PoC")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze"); a.add_argument("case"); a.add_argument("--sig", required=True); a.add_argument("--out", required=True)
    b = sub.add_parser("batch"); b.add_argument("runs"); b.add_argument("--sig", required=True); b.add_argument("--out", required=True)
    b.add_argument("--reports", help="실행별 보고서를 저장할 폴더(선택)")
    fz = sub.add_parser("freeze"); fz.add_argument("--sig", required=True); fz.add_argument("--out", default="freeze_manifest.json")
    args = ap.parse_args(argv)

    if args.cmd == "freeze":
        here = os.path.dirname(os.path.abspath(__file__))
        files = [os.path.abspath(args.sig)] + [os.path.join(here, x) for x in ("wipetrace.py", "evaluate.py") if os.path.exists(os.path.join(here, x))]
        man = {"frozen_at_utc": fmt(dt.datetime.utcnow()), "version": __version__,
               "sha256": {os.path.basename(p): sha256(p) for p in files}}
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(man, f, ensure_ascii=False, indent=2)
        print(json.dumps(man, ensure_ascii=False, indent=2))
        return 0

    sig = load_signatures(args.sig)
    if args.cmd == "analyze":
        res = analyze(args.case, sig)
        write_report(res, args.out)
        print(json.dumps(summary_row(res), ensure_ascii=False))
        return 0

    cases = [os.path.join(args.runs, d) for d in sorted(os.listdir(args.runs)) if os.path.isdir(os.path.join(args.runs, d))]
    with open(args.out, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_FIELDS)
        w.writeheader()
        for c in cases:
            res = analyze(c, sig)
            if args.reports:
                write_report(res, os.path.join(args.reports, res["case"]))
            w.writerow(summary_row(res))
            print(f"{res['case']}: stage {res['stage']} {res['stage_text']} {res['candidate_tools']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
