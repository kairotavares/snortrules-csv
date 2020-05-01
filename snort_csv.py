import snortparser.snortparser
import csv
import sys



RULES_FILE = sys.argv[1]
OUTPUT_FILE = sys.argv[2]

def read_rules(path, filter_commented_rules=True):
    rules = []
    with open(path, 'rb') as f:
        rules = f.read()

    parsed_rules = [snortparser.snortparser.Parser(active_rule.decode("utf-8"))
             for active_rule in rules.splitlines()
             if not active_rule.startswith(b'#') and len(active_rule) > 0]
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

def write_to_file(header, rows):
    with open(OUTPUT_FILE, "w") as outfile:
        csvwriter = csv.writer(outfile)
        csvwriter.writerow(header)
        for row in rows:
            csvwriter.writerow(to_row_value(row))

rules = read_rules(RULES_FILE)
header = list(get_keys(rules[0].header))
header.append('msg')
write_to_file(header, rules)
print("Done")
