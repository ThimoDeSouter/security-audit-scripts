#!/usr/bin/python

# requirements:
#	- python-docx
#	-elementtree

import os
import time
import elementtree
from docx import Document
from docx.shared import Inches
import parsenessus
import parsenmap
from host import Host
from service import Service
from vulnerability import Vulnerability

#init variables
document = Document()
hosts = []
path = os.environ['HOME']+'/Desktop/audit-scans/'


def main():

	print("Welcome to the Audit Report Builder\r\n")

	date = time.strftime("%d/%m/%Y")
	school_name = raw_input("Please enter the school name: ")

	#read all files from the folder that start with the date(user input)
	audit_date = raw_input('please enter the audit date in format: yyyy-mm-dd: ')
	#print 'audit date = ' + audit_date

	#add nmap hosts
	nmaphosts = add_hosts('nmap',audit_date)

	if( len(nmaphosts) == 0):
		print('no nmaphosts found, exiting')
		exit()

	print('please export the nessus scans as .nessus, to the ' + str(path) + ' folder and rename them so they start with the current date')
	cont = raw_input("press enter to continue")

	#add nessus hosts
	nessushosts = add_hosts('nessus',audit_date)

	#mash hosts info together
	for nmaphost in nmaphosts:
		current = find_host(nessushosts,nmaphost.ip)
		if current is not None:
			if (nmaphost.mac is None): nmaphost.mac = current.mac
			if (nmaphost.os is None): nmaphost.os = current.os
			nmaphost.vulnerabilities = current.vulnerabilities
			hosts.append(nmaphost)
		else:
			hosts.append(nmaphost)

	severity = raw_input("vulnerability severity should be at least? (1-9): ")

	all_hosts_by_ip = []
	#select hosts
	print('all hosts in database: \n')
	for host in hosts:
		print ( str(host.ip) + '\n')
		all_hosts_by_ip.append(host.ip)

	print ("enter the hosts you want, 'all' to select all hosts, or 'stop' to stop")
	selected_hosts = []
	maxLength = len(hosts)
	while len(selected_hosts) < maxLength:
		item = raw_input("Host: ")
		if (item == 'stop'):
			break
		if(item == 'all'):
			selected_hosts = all_hosts_by_ip
			break
		selected_hosts.append(item)


	print('debug: selected_hosts ')
	for sel_host in selected_hosts:
		print str(sel_host)

	build_table(hosts,severity,selected_hosts)

	document.save(os.environ['HOME'] + '/Desktop/audit-report-' + school_name + '.docx')
	print 'audit-report-'+school_name+ '.docx saved in' + os.environ['HOME']+'/Desktop'
	return


def find_host(hosts,ip):
	foundHost = None
	for host in hosts:
		if(host.ip == ip):
			print ('found match for ' + str(ip) )
			foundHost = host
	return foundHost


def add_hosts(type,audit_date):
	print('looking for ' + str(type) + ' hosts')
	filetype = None
	if(type) == "nmap":
		filetype = ".xml"
	if(type) == "nessus":
		filetype = ".nessus"

	if not os.path.exists(path):
		print 'Please run the nmapscan.py program first'
		exit()

	scans = []
	for file in os.listdir(path):
		if os.path.isfile(os.path.join(path,file)) and file.startswith(audit_date) and file.endswith(filetype):
			scans.append(file)

	print 'found ' + str(len(scans)) + ' scans'

	hosts = []
	for scan in scans:
		file_path = str(path) +str(scan)

		if(type == "nmap"):
			hostslocal = parsenmap.main(file_path)
		if(type =="nessus"):
			hostslocal = parsenessus.main(file_path)

		for hostlocal in hostslocal:
			duplicate = None
			duplicatehost = None
			for host in hosts:
				if host.ip == hostlocal.ip:
					duplicate = True
					duplicatehost = host
			if(duplicate):
				if( len(hostlocal.services) > len(duplicatehost.services) ):
					hosts.remove(duplicatehost)
					hosts.append(hostlocal)
			else:
				hosts.append(hostlocal)

	print('returning ' + str(len(hosts)) + ' unique ' + str(type) + ' hosts')
	return hosts

def build_table(hosts,severity,selected_hosts):

	#select hosts
	myhosts = []
	for shost in selected_hosts:
		x = find_host(hosts,shost)
		if(x is not None):
			myhosts.append(x)

	for host in myhosts:
		services = host.services
		vulnerabilities = host.vulnerabilities
		rowcount = len(services)

		#main table
		main_table = document.add_table(rows=0, cols=1)
		main_table.autofit = False

		#info section
		info_section = main_table.add_row()
		info_section.cells[0].text = 'Ip: ' + str(host.ip) + '\n' + 'Hostname: ' + str(host.hostname) + ' \n' + 'Operating System: ' + str(host.os) + '\n' + 'MAC Address: ' + str(host.mac)

		#open services text section
		open_services_section = main_table.add_row()
		open_services_field = open_services_section.cells[0]
		open_services_field.text = 'Detected open services:'
		open_services_run = open_services_field.paragraphs[0].runs[0]
		open_services_run.font.bold = True

		#services section
		services_section = main_table.add_row()
		services_table = services_section.cells[0].add_table(rows=0, cols=4)

		#header row services
		header_row = services_table.add_row()

		name_header = header_row.cells[0]
		name_header.text = "Name"
		name_run = name_header.paragraphs[0].runs[0]
		name_run.font.bold = True

		port_header = header_row.cells[1]
		port_header.text = "Port"
		port_run = port_header.paragraphs[0].runs[0]
		port_run.font.bold = True

		protocol_header = header_row.cells[2]
		protocol_header.text = "Protocol"
		protocol_run = protocol_header.paragraphs[0].runs[0]
		protocol_run.font.bold = True

		info_header = header_row.cells[3]
		info_header.text = "Info"
		info_run = info_header.paragraphs[0].runs[0]
		info_run.font.bold = True

		for service in services:
			row = services_table.add_row()
			row.cells[0].text = service.name
			row.cells[1].text = service.port
			row.cells[2].text = service.protocol
			row.cells[3].text = str(service.product) + ' ' + str(service.extrainfo) + ' ' + str(service.version)


		#vulnerabilities text section
		vulns_section = main_table.add_row()
		vulns_field = vulns_section.cells[0]
		vulns_field.text = 'Detected vulnerabilities: \n'
		vulns_run = vulns_field.paragraphs[0].runs[0]
		vulns_run.font.bold = True


		#vulnerabilities section
		vulnerabilities_section = main_table.add_row()
		vulnerabilities_table = vulnerabilities_section.cells[0].add_table(rows=0,cols=2)
		vulnerabilities_table.autofit = False
		vulnerabilities_table.columns[0].width = Inches(1.5)
		vulnerabilities_table.columns[1].width = Inches(4.5)


		#header row vulns
		header_row = vulnerabilities_table.add_row()

		severity_header = header_row.cells[0]
		severity_header.text = "Severity"
		severity_run = severity_header.paragraphs[0].runs[0]
		severity_run.font.bold = True

		description_header = header_row.cells[1]
		description_header.text = "Name"
		description_run = description_header.paragraphs[0].runs[0]
		description_run.font.bold = True


		for vulnerability in vulnerabilities:
			if (vulnerability.severity >= severity):
				row = vulnerabilities_table.add_row()
				row.cells[0].text = vulnerability.severity
				row.cells[1].text = vulnerability.name

		document.add_paragraph("")
	return

if __name__ == "__main__":
	main()
