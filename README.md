A collection of python scripts that can help to automate the process of a security audit. In particular scanning and generating a report.

###Requirements:
software:
  - python
  - nmap
  - nessus (free edition)
  
python modules:
  - elementtree
  - python-docx
    
	
###Usage:
Run 'nmapscan.py' & 'nessusscan.py', follow on-screen instructions.
(It's recommended to use option 4 in nmapscan.py) 
Once all scans are done, run 'makereport.py'


###How to install the dependencies:

'tar xvzf elementtree-1.2.6-20050316.tar.gz' --> 'cd elementtree-1.2.6-20050316' --> 'python setup.py install'  
'tar xvzf python-docx-0.8.6.tar.gz' --> 'cd python-docx-0.8.6' --> 'python setup.py install'   

Thanks go out to Yellis for supplying the original nmap script.
