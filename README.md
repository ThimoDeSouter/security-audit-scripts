Python scriptje dat de resultaten van nmap en nessus scans per host in een tabel in Word dumpt.

Gebruik:
Eerst alle scans uitvoeren; nmap via nmapscan.py, en nessus manueel via de browser. 
Voor beste resultaat de 'intense scan (4) optie gebruiken bij nmap.
Daarna de nessus scans in '.nessus' formaat exporteren naar '/user/Desktop/audit-scans' (aangemaakt door nmapscan) en hernoemen zodat de file begint met de datum van de scan. Vb: '2016-12-1-scan1.nessus'
De nmapscans zullen zelf in die folder geplaats worden.
Ten slotte 'makereport.py' uitvoeren, en de instructies op het scherm volgen.

Installatie:
'tar xvzf elementtree-1.2.6-20050316.tar.gz' --> 'cd elementtree-1.2.6-20050316' --> 'python setup.py install'
'tar xvzf python-docx-0.8.6.tar.gz' --> 'cd python-docx-0.8.6' --> 'python setup.py install' 

Dank aan Yellis voor het originele nmapscan script