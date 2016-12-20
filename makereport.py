#!/usr/bin/python

import os
import sys
import time
import elementtree
from docx import Document
from docx.shared import Inches
import parsenessus
import parsenmap
from host import Host
from service import Service
from vulnerability import Vulnerability

from docx.oxml.ns import nsdecls
from docx.oxml import parse_xml
from docx.enum.text import WD_ALIGN_PARAGRAPH

#init variables
document = Document()
hosts = []
path = os.environ['HOME']+'/Desktop/audit-scans/'


def main():
	os.system('clear')
	print("Welcome to the Audit Report Builder")
	print("Run this after completing the nmapscan and nessusscan programs")

	date = time.strftime("%d/%m/%Y")
	school_name = raw_input("Please enter the school name: ")

	#read all files from the folder that start with the date(user input)
	audit_date = raw_input('please enter the audit date in format: yyyy-mm-dd: ')


	#add nmap hosts
	nmaphosts = add_hosts('nmap',audit_date)

	if( len(nmaphosts) == 0):
		print('no nmaphosts found, exiting')
		exit()

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

	nrOfServices = int(raw_input("Minimum number of detected services? (nmap): "))
	severity = float(raw_input("vulnerability severity should be at least? (0.0 - 10.0): "))

	all_hosts_by_ip = []
	#select hosts
	print('all hosts in database: \n')
	for host in hosts:
		print ( str(host.ip) + '\r')
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
		else:
			selected_hosts.append(item)

	print 'generating report...'

	#build front page
	howest_img_p = document.add_paragraph()
	howest_img_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
	img_r = howest_img_p.add_run()
	img_r.add_picture('howest.jpg', width=Inches(4.9))

	front_page1 = document.add_paragraph("Computer & CyberCrime Professional\n\n")
	front_page1.alignment = WD_ALIGN_PARAGRAPH.CENTER
	front_page1.style = document.styles['Heading 5']

	front_page = document.add_paragraph("Audit report for:")
	front_page.alignment = WD_ALIGN_PARAGRAPH.CENTER
	front_page.style = document.styles['Heading 2']

	front_page0 = document.add_paragraph(str(school_name))
	front_page0.alignment = WD_ALIGN_PARAGRAPH.CENTER
	front_page0.style = document.styles['Heading 1']


	front_page2 = document.add_paragraph("Conducted on: " +str(audit_date))
	front_page2.alignment = WD_ALIGN_PARAGRAPH.CENTER
	front_page2.style = document.styles['Heading 3']

	document.add_paragraph("\n\n\n\n\n\n\n\n\n\n\n\n\n")

	front_page3 = document.add_paragraph("Report generated with: \n http://github.com/thimoDeSouter/security-audit-scripts")
	front_page3.alignment = WD_ALIGN_PARAGRAPH.CENTER
	front_page3.style = document.styles['Heading 6']

	document.add_page_break()
	#end build front page

	build_table(hosts,severity,selected_hosts,nrOfServices)

	document.save(os.environ['HOME'] + '/Desktop/audit-report-' + school_name + '.docx')
	print 'audit-report-'+school_name+ '.docx saved in' + os.environ['HOME']+'/Desktop'
	return


def find_host(hosts,ip):
	foundHost = None
	for host in hosts:
		if(host.ip == ip):
			foundHost = host
	return foundHost


def add_hosts(type,audit_date):
	filetype = None
	if(type) == "nmap":
		filetype = ".xml"
	if(type) == "nessus":
		filetype = ".nessus"

	if not os.path.exists(path):
		print 'Please run nmapscan or nessusscan first'
		exit()

	scans = []
	for file in os.listdir(path):
		if os.path.isfile(os.path.join(path,file)) and file.startswith(audit_date) and file.endswith(filetype):
			scans.append(file)

	print 'found ' + str(len(scans)) + ' ' + str(type) + ' scans'

	print ('processing...')

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

	return hosts

def build_table(hosts,severity,selected_hosts,nrOfServices):

	#select hosts
	myhosts = []
	for shost in selected_hosts:
		x = find_host(hosts,shost)
		if( (x is not None) and (len(x.services) >= nrOfServices) ):
			myhosts.append(x)

	hostcount_total = len(myhosts)
	count = 0
	for host in myhosts:
		#progress
		count +=1
		sys.stdout.write("\rProcessed host({0} of ".format(count))
		sys.stdout.flush()
		print(str(hostcount_total)+")")

		services = host.services
		vulnerabilities = host.vulnerabilities
		rowcount = len(services)

		#main table
		main_table = document.add_table(rows=0, cols=1)
		main_table.autofit = False

		#info section
		info_section = main_table.add_row()

		p_info = info_section.cells[0].paragraphs[0]
		p_info.add_run('IP: ').bold = True
		p_info.add_run(str(host.ip)+'\n')

		p_info.add_run('Hostname: ').bold = True
		p_info.add_run(str(host.hostname)+'\n')

		p_info.add_run('Operating System: ').bold = True
		p_info.add_run(str(host.os)+'\n')

		p_info.add_run('MAC Address: ').bold = True
		p_info.add_run(str(host.mac))


		#open services text section
		open_services_section = main_table.add_row()
		open_services_p = open_services_section.cells[0].paragraphs[0]
		open_services_p.add_run('Detected Open Services:').bold = True

		#services section
		services_section = main_table.add_row()
		remove_p = services_section.cells[0].paragraphs[0]
		p = remove_p._element
		p.getparent().remove(p)
		p._p = p._element = None
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
			row.cells[3].text = row.cells[3].text.replace('None',' ')


		if ( (len(vulnerabilities) >= 1)):
			vulnprint = False
			for vuln in vulnerabilities:
				if( vuln.base_score >= severity):
					vulnprint = True

			if(vulnprint):
				#vulnerabilities text section
				vulns_section = main_table.add_row()
				vulns_p = vulns_section.cells[0].paragraphs[0]
				vulns_p.add_run('Detected Vulnerabilities:').bold = True


				#vulnerabilities section
				vulnerabilities_section = main_table.add_row()
				vuln_p_rem = vulnerabilities_section.cells[0].paragraphs[0]
				p2 = vuln_p_rem._element
				p2.getparent().remove(p2)
				p2._p2 = p2._element = None

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
				description_header.text = "Description"
				description_run = description_header.paragraphs[0].runs[0]
				description_run.font.bold = True


				#actual vuls
				vulnerabilities.sort(key=lambda x: float(x.base_score), reverse=True)
				for vulnerability in vulnerabilities:
					if (vulnerability.base_score >= severity):
						row = vulnerabilities_table.add_row()
						row.cells[0].text = str(vulnerability.base_score)

						sev = float(vulnerability.base_score)

						#set vuln color
						if( sev >= 9.5): #critical
							shading_elm = parse_xml(r'<w:shd {} w:fill="ff0000"/>'.format(nsdecls('w')))
							row.cells[0]._tc.get_or_add_tcPr().append(shading_elm)

						elif( sev <= 9.4 and sev >=7.6): #high
							shading_elm = parse_xml(r'<w:shd {} w:fill="ee7600"/>'.format(nsdecls('w')))
							row.cells[0]._tc.get_or_add_tcPr().append(shading_elm)

						elif( sev <= 7.5 and sev >=4.0): #medium
							shading_elm = parse_xml(r'<w:shd {} w:fill="ffa500"/>'.format(nsdecls('w')))
							row.cells[0]._tc.get_or_add_tcPr().append(shading_elm)

						elif( sev <=3.9 and sev >=1.1): #low
							shading_elm = parse_xml(r'<w:shd {} w:fill="00ff00"/>'.format(nsdecls('w')))
							row.cells[0]._tc.get_or_add_tcPr().append(shading_elm)

						elif( sev <=1.0): #info
							shading_elm = parse_xml(r'<w:shd {} w:fill="0000ff"/>'.format(nsdecls('w')))
							row.cells[0]._tc.get_or_add_tcPr().append(shading_elm)



						#p = row.cells[1].add_paragraph()
						p = row.cells[1].paragraphs[0]
						p.add_run('Name: ').bold = True
						p.add_run(str(vulnerability.name)+'\n')

						p.add_run('Synopsis: ').bold = True
						p.add_run(str(vulnerability.synopsis)+'\n')

						p.add_run('CVE: ').bold = True
						p.add_run(str(vulnerability.cve)+'\n')

						p.add_run('CVE Date: ').bold = True
						p.add_run(str(vulnerability.pub_date)+'\n')

						p.add_run('Score: ').bold = True
						p.add_run(str(vulnerability.severity)+'\n')

						p.add_run('Solution: ').bold = True
						p.add_run(str(vulnerability.solution))

		document.add_paragraph("")
	return

if __name__ == "__main__":
	main()
