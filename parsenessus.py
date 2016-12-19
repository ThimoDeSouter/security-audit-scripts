#!/usr/bin/python

import elementtree.ElementTree as ET
import sys
import getopt
from host import Host
from vulnerability import Vulnerability


def main(argument):
	hosts = []

	try:
		tree = ET.parse(argument)
		root = tree.getroot()

	except:
		print ('error when parsing file: ' + str(argument))
		print ('most likely caused by a malformed .nessus (xml) file')

	populateList(root, hosts)

	return hosts


def populateList(root,hosts):

	reporthostnodes = root.findall('.//ReportHost')

	for reporthostnode in reporthostnodes:
		#find host info
		hostip = reporthostnode.attrib['name']
		hostos = None
		hostfqdn = None
		hostmac = None

		hosttags = reporthostnode.findall('HostProperties/tag')
		for hosttag in hosttags:
			if(hosttag.attrib['name'] == "operating-system"):
				hostos = hosttag.text
			if(hosttag.attrib['name'] == "host-fqdn"):
				hostfqdn = hosttag.text
			if(hosttag.attrib['name'] == "mac-address"):
				hostmac = hosttag.text

			host = Host(hostip, hostos, hostfqdn, hostmac)


		reportitems = reporthostnode.findall('ReportItem')

		for reportitem in reportitems:

			port=name=protocol=severity=description=cve=synopsis=solution=pub_date = None
			base_score = 0.0

			port = reportitem.attrib['port']
			name = reportitem.attrib['pluginName']
			protocol = reportitem.attrib['protocol']
			severity = reportitem.attrib['severity']
			description = reportitem.find('description').text
			synopsis = reportitem.find('synopsis').text
			solution = reportitem.find('solution').text

			cve_obj = reportitem.find('cve')
			if cve_obj is not None:
				cve = cve_obj.text

			base_score_obj = reportitem.find('cvss_base_score')
			if base_score_obj is not None:
				base_score = base_score_obj.text


			pub_date_obj = reportitem.find('vuln_publication_date')
			if pub_date_obj is not None:
				pub_date = pub_date_obj.text



			vuln = Vulnerability()
			vuln.name = name
			vuln.port = port
			vuln.protocol = protocol
			vuln.description = description
			vuln.severity = severity
			vuln.cve = cve
			vuln.base_score = base_score
			vuln.synopsis = synopsis
			vuln.solution = solution
			vuln.pub_date = pub_date

			host.addVulnerability(vuln)
		hosts.append(host)
