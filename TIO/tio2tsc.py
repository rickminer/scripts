#!/usr/bin/env python

from tenable.io import TenableIO

tio = TenableIO('044365a8a7bb159c5d25230567dd6227cea21f86de4d88dced688f8bd1431918', '04a19e7db27afe32f039ee19d199fe710c8da88b3b18bddc23bccb7091947ae8')

for scan in tio.scans.list():
    with open(scan['name'] + '.nessus','wb') as reportobj:
        results = tio.scans.export(int(scan['id']),fobj=reportobj)