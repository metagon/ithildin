#!/usr/bin/env python3

import csv
import sys
from argparse import ArgumentParser
from os.path import dirname, realpath
from sys import argv, exit

parent_dir = dirname(dirname(realpath(__file__)))
sys.path.append(parent_dir)

from ithildin.loader.contract_loader_factory import get_factory, LoaderFactoryType
from ithildin.analysis.symbolic import LaserWrapper

parser = ArgumentParser()
parser.add_argument('filename', metavar='FILE', type=str)
parser.add_argument('--infura-project', dest='infura_project_id', metavar='PROJECT_ID', type=str, required=True)
parser.add_argument('--input-limit', dest='input_limit', metavar='SIZE', type=int, default=5)
parser.add_argument('--exec-timeout', dest='exec_timeout', metavar='SEC', type=float, default=90)


def benchmark():
    args = parser.parse_args()
    rpc = 'https://mainnet.infura.io/v3/' + args.infura_project_id
    with open(args.filename, 'r') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=';')
        next(csv_reader, None)  # ignore header
        i = 0
        for row in csv_reader:
            if i >= args.input_limit:
                break
            i += 1
            target_address = row[0]
            print('[%d/%d] Analyzing contract at %s' % (i, args.input_limit, target_address))
            loader_factory = get_factory(LoaderFactoryType.WEB3, address=target_address, rpc=rpc)
            report = LaserWrapper().execute(contract_loader=loader_factory.create(), timeout=args.exec_timeout)
            has_results = False
            for report_item in report.reports:
                if len(report_item.results) > 0:
                    has_results = True
                    break
            if has_results:
                print(report.to_text())
            else:
                print('Nothing found...')


if __name__ == '__main__':
    benchmark()
    exit(0)
