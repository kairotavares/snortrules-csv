import snortparser.snortparser
import csv
import sys
from os import listdir
from os.path import isfile, join

ignore_list = ['snort3-deleted.rules']

def is_rule(rule_line):
    return len(rule_line) > 100

def read_rules(path, filter_commented_rules=True):
    rules = []
    with open(path, 'rb') as f:
        rules = f.read()

    parsed_rules = [snortparser.snortparser.Parser(active_rule.decode("utf-8").replace("#", ""))
             for active_rule in rules.splitlines()
             if is_rule(active_rule)]
    return parsed_rules

def get_keys(row):
    return row.keys()

def parse_port(value):
    if "$" in value or ":" in value:
        return value
    return int(value)

def to_row_value(row):
    values = []
    for _, value in row.header.items():
        if type(value) == tuple:
            has_data, data = value
            if type(data) == list:
                data_list = [parse_port(data_tuple) for has_data_tuple, data_tuple in data if has_data_tuple]
                values.append(data_list)
            else:
                values.append(data) if has_data else values.append('')
        else:
            values.append(value)
    _, msg = row.options[0]
    values.append(msg[0])
    return values

def write_to_file(output_file, header, rows):
    with open(output_file, "w") as outfile:
        csvwriter = csv.writer(outfile)
        csvwriter.writerow(header)
        for row in rows:
            csvwriter.writerow(to_row_value(row))

def process_single_file(rules_file, output_file):
    rules = read_rules(rules_file)
    header = list(get_keys(rules[0].header))
    header.append('msg')
    write_to_file(output_file, header, rules)
    print("Done")

def process_multiple_files(rules_files, output_file):
    rules = []
    for file in rules_files:
        print(file)
        file_rules = read_rules(file)
        rules.extend(file_rules)
    print(len(rules))
    header = list(get_keys(rules[0].header))
    header.append('msg')
    write_to_file(output_file, header, rules)
    print("Done")

if __name__ == '__main__':
    rules_path = sys.argv[1]
    output_file = sys.argv[2]

    if isfile(rules_path):
        process_single_file(rules_path, output_file)
    else:
        files = [join(rules_path, f) for f in listdir(rules_path)
                 if isfile(join(rules_path, f)) and '.rules' in f and f not in ignore_list]
        process_multiple_files(files, output_file)