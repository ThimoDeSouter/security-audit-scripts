#!/usr/bin/python

import elementtree.ElementTree as ET
import sys
import getopt
from host import Host
from service import Service


def main(argument):
	tree = ET.parse(argument)
	root = tree.getroot()
	hosts = []
	populateList(root, hosts)
	#printList(hosts)
	return hosts


def populateList(root,hosts):

	hostnodes = root.findall('.//host')

	for hostnode in hostnodes:
		addressnode = hostnode.find('address')
		address = (addressnode.attrib['addr'])
		hoststatusnode = hostnode.find('status')
		hoststatus = hoststatusnode.attrib['state']

		if hoststatus =='up':
			#find OS (first match only = highest accuracy)
			os = None
			osmatch = hostnode.find('os/osmatch')
			if osmatch is not None:
				if 'name' in osmatch.attrib:
					os = osmatch.attrib['name']

			hostname = None
			hostnamenode = hostnode.find('hostnames/hostname')
			if hostnamenode is not None:
				if 'name' in hostnamenode.attrib:
					hostname = hostnamenode.attrib['name']

			host = Host(address,os,hostname,None)

			ports = hostnode.findall('ports/port')
			for port in ports:
				servicenode = port.find('service')
				state = port.find('state')
				service = Service()

				if 'name' in servicenode.attrib:
					service_name = servicenode.attrib['name']
					service.name = service_name

				if 'portid' in port.attrib:
					port_portid = port.attrib['portid']
					service.port = port_portid

				if 'protocol' in port.attrib:
					port_protocol = port.attrib['protocol']
					service.protocol = port_protocol

				if 'state' in state.attrib:
					state_state = state.attrib['state']
					service.state = state_state

				if 'product' in servicenode.attrib:
					service_product = servicenode.attrib['product']
					service.product = service_product

				if 'extrainfo' in servicenode.attrib:
					service_extrainfo = servicenode.attrib['extrainfo']
					service.extrainfo = service_extrainfo

				if 'version' in servicenode.attrib:
					service_version = servicenode.attrib['version']
					service.version = service_version

				host.addService(service)
			hosts.append(host)
	return

