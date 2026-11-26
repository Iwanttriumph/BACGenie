if __package__ in (None, ""):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import argparse
import json
import re
import sys
from pathlib import Path
from src.config import ROOT, MODEL
from src.toolbox.file_ops import read_json, write_json, atomic_write
from src.toolbox.llm_client import Client, get_key, run_stage
from src.toolbox.validation import schemas, validate
from src.toolbox.classification import classify
from src.agents.trigger_extractor import process
from src.agents.oracle_designer import process_oracle
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--input", type=Path)
    group.add_argument("--input-dir", type=Path,
                       help="批量读取目录下的 CVE-*.json 平面输入")
    group.add_argument("--cve")
    parser.add_argument("--results-dir", type=Path, default=ROOT / "results",
                        help="输出保存目录；未指定 --input/--input-dir 时也用于发现已有输入（默认 results）")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--stage", choices=["tp", "oracle", "all"], default="tp")
    args = parser.parse_args()
    results = args.results_dir
    if args.cve and not re.fullmatch(r"CVE-\d{4}-\d{4,}", args.cve):
        parser.error("--cve 必须为合法 CVE ID")
    if args.input_dir and not args.input_dir.is_dir():
        parser.error("--input-dir 必须是已存在的目录")
    if args.input:
        paths = [args.input]
    elif args.input_dir:
        paths = sorted(args.input_dir.glob("CVE-*.json"))
        if not paths:
            parser.error("--input-dir 中未找到 CVE-*.json")
    elif args.cve:
        paths = [results / args.cve / (args.cve + ".json")]
    else:
        paths = sorted(p for p in results.glob("CVE-*/*.json") if p.stem == p.parent.name)
    counts = {"success": 0, "ready": 0, "incomplete": 0, "failed": 0, "skipped": 0}
    for path in paths:
        try:
            factory = lambda: Client(get_key(), model=args.model)
            status = process(path, results, factory, args.overwrite) if args.stage != "oracle" else "skipped"
            if args.stage != "tp" and status != "failed":
                status = process_oracle(path, results, factory, args.overwrite)
        except Exception as error:
            print(f"输入错误 {path}: {error}", flush=True)
            status = "failed"
        counts[status] += 1
    print(json.dumps(counts, ensure_ascii=False))
    return 1 if counts["failed"] else 0



if __name__ == "__main__":
    sys.exit(main())
