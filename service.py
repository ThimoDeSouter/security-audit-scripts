class Service:

	def __init__(self):
		self.name = None
		self.port = None
		self.protocol = None
		self.state = None
		self.product = None
		self.extrainfo = None
		self.version =None

	def __str__(self):
		return ' ' + str(self.name) + ' ' +  str(self.port) + ' ' +  str(self.protocol) + str(self.state) + str(self.product) + str(self.extrainfo) + str(self.version) + ' '
