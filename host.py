class Host:

	def __init__(self,ip,os,hostname,mac):
		self.services = []
		self.vulnerabilities = []
		self.ip = ip
		self.os = os
		self.hostname = hostname
		self.mac = mac
		self.nikto = None
	def addService(self,service):
		self.services.append(service)
	def addVulnerability(self,vulnerability):
		self.vulnerabilities.append(vulnerability)
	def display(self):
		print 'Host: '+self.ip+ ' has ' + str(len(services)) + ' services and ' + str(len(vulnerabilities)) + ' vulnerabilities'

def printList(hosts):

	for host in hosts:
		host.display()
		print ''
	return
