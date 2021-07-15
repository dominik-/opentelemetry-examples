import json
from typing import Set

def ParseToDict(fileName):
    with open(fileName, "r") as inputFile:
        return json.load(inputFile)

def CountOccurences(results, rules):
    #if no rules are specified, we want to count occurences of all triggered rules -> get unique rule IDs
    if len(rules) == 0:
        print('No rule specified, running analysis of all rules...')
        rules = getUniqueRules(results)
    ensureKeyPrefixes(rules, "semgrep-rules.")
    print(f'Applying analysis to {len(rules)} rules.')
    print(rules)
    occurencesMap = {}
    #Results are keyed under "results"
    for result in results["results"]:
        id = result["check_id"]
        if id in rules:
            if id in occurencesMap:
                occurencesMap[result["check_id"]] = occurencesMap[result["check_id"]] + 1
            else:
                occurencesMap[result["check_id"]] = 1
    return occurencesMap

def getUniqueRules(results):
    result_ids = []
    for result in results["results"]:
        #Only add results that have the severity-level of INFO, because these reflect values to accumluate in metrics.
        if result["extra"]["severity"] == "INFO":
            result_ids.append(result["check_id"])
    return list(set(result_ids))

def ensureKeyPrefixes(listOfStrings, prefix):
    for i in range(0, len(listOfStrings)):
        if not listOfStrings[i].startswith(prefix):
            listOfStrings[i] = prefix + listOfStrings[i]