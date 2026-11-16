"""Command line entry: sniff a directory and emit a JSON report."""

import argparse
import os

from . import report, rules


def iter_files(directory):
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            yield path


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="filetypes", description=__doc__
    )
    parser.add_argument("--dir", required=True,
                        help="directory of files to sniff")
    parser.add_argument("--out", required=True,
                        help="path of the JSON report to write")
    args = parser.parse_args(argv)

    records = []
    for path in iter_files(args.dir):
        detected, declared, verdict, evidence = rules.analyze_file(path)
        records.append(
            report.make_record(path, detected, declared, verdict, evidence)
        )

    report.write_report(records, args.out)
    total, allowed, rejected = report.summarize(records)
    print("files=%d allowed=%d rejected=%d" % (total, allowed, rejected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
