#!/usr/bin/env python

import os
#https://github.com/tenable/pyTenable
#https://pytenable.readthedocs.io/en/stable/io.html
from tenable.io import TenableIO
#https://pytenable.readthedocs.io/en/stable/sc.html
from tenable.sc import TenableSC
import tenable.errors

tio = TenableIO('044365a8a7bb159c5d25230567dd6227cea21f86de4d88dced688f8bd1431918', '04a19e7db27afe32f039ee19d199fe710c8da88b3b18bddc23bccb7091947ae8')

scans = []
for scan in tio.scans.list():
    print(scan['name'])
    try:
        with open(scan['name'] + '.nessus','wb') as reportobj:
            tio.scans.export(int(scan['id']),fobj=reportobj)
            scans.append(scan['name'] + '.nessus')
            break
    except tenable.errors.InvalidInputError as err:
        os.remove(scan['name'] + '.nessus')

tsc = TenableSC('sccv03.csp.noaa.gov')
tsc.login('scriptuser', 'L9ir&wN$TdgZLDH#$$28')

# # Get the list of repositories as a list
repos = tsc.repositories.remote_fetch('sccv03.csp.noaa.gov')

# for report in scans:
#     with open(report) as fobj:
#         # Translate scan to Repository
        
#         # import_scan(fobj, repo, auto_mitigation, host_tracking, vhosts)
#         # Parameters:	
#         # fobj (FileObject) – The file-like object containing the Nessus file to import.
#         # repo (int) – The repository id for the scan.
#         # auto_mitigation (int, optional) – How many days to hold on to data before mitigating it? The default value is 0.
#         # host_tracking (bool, optional) – Should DHCP host tracking be enabled? The default is False.
#         # vhosts (bool, optional) – Should virtual host logic be enabled for the scan? The default is False.
#         tsc.scan_instances.import_scan(fobj,"REPOSITORY_ID")