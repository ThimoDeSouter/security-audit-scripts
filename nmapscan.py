import os
import datetime
import time

today = datetime.date.today()
timestamp = ( str(today.year) + '-' + str(today.month) + '-' + str(today.day))
print 'DEBUG, timestamp = ' + str(timestamp)

def get_nmap(options, ip):
    command = "nmap " + options + " " + ip;
    process = os.popen(command)
    results = str(process.read())
    return results

#output directory : /username/Desktop/audit-nmap-scans/
#create if not exists
outputdir = os.environ['HOME']+'/Desktop/audit-scans/'

if not os.path.exists(outputdir):
	print 'creating output dir:'
	print outputdir
	os.makedirs(outputdir)


print "Hello and welcome to this nmap script."
print "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
print "below this line you can choose the scan you want to perfom"
print "1. fast scan"
print "2. ping scan"
print "3. regular scan"
print "4. intense scan"
print "5. intense scan, all TCP ports "
print "6. quick traceroute scan"
print "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

number = raw_input("Which scan do you want to perform? ")
ip = raw_input("What ip address or range do you want to scan? ")

cleanip = ip.replace('/','#')

file_name = None

if number == "1":
	(get_nmap("-F -oX " + outputdir +timestamp+"-fast_scan_"+cleanip+".xml", ip))
	file_name = timestamp + '-fast_scan_' + cleanip + '.xml'
elif number == "2":
	get_nmap("-sn -oX " + outputdir + timestamp + "-ping_scan_" +cleanip+ ".xml", ip)
	file_name = timestamp + '-ping_scan_' + cleanip + '.xml'
elif number == "3":
	get_nmap("-oX " + outputdir + timestamp + "-regular_scan_" +cleanip+ ".xml",ip)
	file_name = timestamp + '-regular_scan_' + cleanip + '.xml'
elif number == "4":
	get_nmap("-T4 -A -v -oX " + outputdir + timestamp + "-intense_scan_" + cleanip + ".xml", ip)
	file_name = timestamp + '-intense_scan' + cleanip + '.xml'
elif number == "5":
	get_nmap("-p 1-65535 -T4 -A -v  -oX " + outputdir + timestamp + "-intenseAllTCP_scan_" + cleanip + ".xml", ip)
	file_name = timestamp + '-intenseAllTCP_scan' + cleanip + '.xml'
elif number == "6":
	get_nmap("-sn --traceroute -oX " + outputdir + timestamp +  "-traceroute_scan_" + cleanip + ".xml", ip)
	file_name = timestamp + '-traceroute_scan' + cleanip + '.xml'

print "scan has been saved in:" + str(outputdir) + str(file_name)
