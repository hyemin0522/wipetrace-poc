#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evaluate.py - wipetrace 결과를 정답표와 대조한다 (정답은 판별기에 넣지 않고 여기서만 사용).

  python evaluate.py results.csv answers.csv [--out eval.md]

answers.csv 열: case, scenario(S0/S1/S2/S3/S4), tool(도구 id 또는 빈칸), use(작성/적용)
  - 양성: scenario == S4 (지정 파일에 완전삭제 기능 적용)
  - 음성: 그 밖의 시나리오
  - 판단 불가: 해당 모드 경보가 빈칸(입력 미수집·파싱 실패) 또는 결과 행 자체가 없음 → TP/FP/FN/TN 에 넣지 않고 U+/U-로 센다
    (따라서 항상 TP+FN+U+ = 양성 수, FP+TN+U- = 음성 수)
"""
import argparse
import csv
from collections import Counter, defaultdict

MODES = [("exec", "alert_exec", "실행 흔적만"), ("journal", "alert_journal", "저널만"), ("both", "alert_both", "실행+저널 결합")]


def load(path, key="case"):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return {r[key]: r for r in csv.DictReader(f)}


def ratio(a, b):
    return f"{a}/{b} ({a / b:.2f})" if b else "계산 불가"


def evaluate(results, answers, use=None):
    sel = [c for c in answers if use is None or answers[c].get("use", "") == use]
    cases = [c for c in sel if c in results]
    missing = [c for c in sel if c not in results]  # 결과 행이 없는 case는 분모에서 빼지 않고 판단 불가(U)로 센다
    out = {"n": len(sel), "missing_results": missing, "modes": {}, "stage_by_scenario": {}, "tool_id": {}}
    for mode, col, _ in MODES:
        m = Counter()
        for c in missing:
            m["U+" if answers[c]["scenario"].strip().upper() == "S4" else "U-"] += 1
        for c in cases:
            pos = answers[c]["scenario"].strip().upper() == "S4"
            v = results[c][col].strip()
            if v == "":
                m["U+" if pos else "U-"] += 1
            elif v == "1":
                m["TP" if pos else "FP"] += 1
            else:
                m["FN" if pos else "TN"] += 1
        out["modes"][mode] = dict(m)
    sb = defaultdict(Counter)
    for c in cases:
        sb[answers[c]["scenario"].upper()][results[c]["stage"]] += 1
    out["stage_by_scenario"] = {k: dict(v) for k, v in sorted(sb.items())}
    s4_missing = sum(1 for c in missing if answers[c]["scenario"].upper() == "S4")
    s4 = [c for c in cases if answers[c]["scenario"].upper() == "S4"]
    single_ok = sum(1 for c in s4 if results[c]["candidate_tools"] == answers[c]["tool"])
    multi = sum(1 for c in s4 if ";" in results[c]["candidate_tools"])
    none = sum(1 for c in s4 if results[c]["candidate_tools"] == "")
    out["tool_id"] = {"S4": len(s4) + s4_missing, "단일 정답": single_ok, "복수 후보": multi, "후보 없음": none,
                      "단일 오답": len(s4) - single_ok - multi - none, "결과 없음": s4_missing}
    return out


def to_markdown(ev, title):
    L = [f"## {title} (실행 {ev['n']}회)", "", "| 모드 | TP | FP | FN | TN | U+ | U- | 재현율 | 오탐률 |", "|---|---|---|---|---|---|---|---|---|"]
    for mode, _, label in MODES:
        m = ev["modes"][mode]
        g = lambda k: m.get(k, 0)
        L.append(f"| {label} | {g('TP')} | {g('FP')} | {g('FN')} | {g('TN')} | {g('U+')} | {g('U-')} | "
                 f"{ratio(g('TP'), g('TP') + g('FN'))} | {ratio(g('FP'), g('FP') + g('TN'))} |")
    L += ["", "시나리오별 판별 단계 분포(단계: 건수)", ""]
    for s, d in ev["stage_by_scenario"].items():
        L.append(f"- {s}: " + ", ".join(f"{k}단계 {v}건" for k, v in sorted(d.items())))
    L += ["", f"도구 식별(S4): {ev['tool_id']}"]
    if ev["missing_results"]:
        L.append(f"\n결과 없음(U로 집계, 확인 필요): {', '.join(ev['missing_results'])}")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results"); ap.add_argument("answers"); ap.add_argument("--out")
    a = ap.parse_args()
    res, ans = load(a.results), load(a.answers)
    parts = [to_markdown(evaluate(res, ans), "전체")]
    uses = sorted({r.get("use", "") for r in ans.values() if r.get("use")})
    for u in uses:
        parts.append(to_markdown(evaluate(res, ans, u), f"{u} 자료"))
    text = "\n\n".join(parts)
    print(text)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    main()
