#!/usr/bin/env python3

from jinja2 import Environment, FileSystemLoader

import re

ANCHOR_START = '-- START AUTO GENERATED CODE'
ANCHOR_END = '-- END AUTO GENERATED CODE'

LUA_TYPES = ('number', 'string', 'table')

data = {
  "x509": __import__("type_x509").defines,
  "csr": __import__("type_x509_req").defines,
  "crl": __import__("type_x509_crl").defines,
}

fl = FileSystemLoader('templates')
env = Environment(loader=fl)

tmpl = {
    "output": env.get_template('x509_functions.j2'),
    "output_test": env.get_template('x509_tests.j2')
}

for k in tmpl:
    for modname in data:
        mod = data[modname]
        output = mod[k]
        ct = None
        with open(output, "r") as f:
            ct = f.read()
        
        repl = tmpl[k].render(
            module=mod,
            modname=modname,
            LUA_TYPES=LUA_TYPES,
        )

        ct = re.sub(
            ANCHOR_START + '.+' + ANCHOR_END,
            ANCHOR_START + '\n' + repl + '\n' + ANCHOR_END,
            ct,
            flags = re.DOTALL,
        )

        open(output, 'w').write(ct)

        print("%-40s: wrote %d functions (%dl)" % (output, len(re.findall("_M:", ct)), len(repl.split('\n'))))