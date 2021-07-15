import argparse

import os
import sys

from analysis import *

analysisCLIParser = argparse.ArgumentParser(prog='tmm',
    description='Produces interesting aggregations of semgrep results.',
    usage='%(prog)s [options] path',
    fromfile_prefix_chars='@')

analysisCLIParser.add_argument('-r', action='append', type=str, help='List of rules to analyze. If not specified, tries to analyze all rules which match the INFO severity.')
analysisCLIParser.add_argument('path', action='store', help='Path to semgrep output file.')

cli_args = analysisCLIParser.parse_args()
if not (cli_args.r):
    rules = []
else:
    rules = cli_args.r

#print(cli_args)

resultsJson = ParseToDict(cli_args.path)
occurrences = CountOccurences(resultsJson, rules)
print(occurrences)