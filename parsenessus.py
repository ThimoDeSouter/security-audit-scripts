#!/usr/bin/python

import elementtree.ElementTree as ET
import sys
import getopt
from host import Host
from vulnerability import Vulnerability


def main(argument):
	tree = ET.parse(argument)
	root = tree.getroot()
	hosts = []
	populateList(root, hosts)
	return hosts


def populateList(root,hosts):

	reporthostnodes = root.findall('.//ReportHost')

	print ('nr of hosts = ' + str(len(reporthostnodes)) )
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
			port = reportitem.attrib['port']
			name = reportitem.attrib['pluginName']
			protocol = reportitem.attrib['protocol']
			severity = reportitem.attrib['severity']
			description = reportitem.find('description').text

			vuln = Vulnerability()
			vuln.name = name
			vuln.port = port
			vuln.protocol = protocol
			vuln.description = description
			vuln.severity = severity

			host.addVulnerability(vuln)
		hosts.append(host)
