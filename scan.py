class Scan:

	def __init__(self,name,description,targets,id):
		self.status = None
		self.name = name
		self.description = description
		self.targets = targets
		self.id = id
		self.history_id = None

	def getStatus(self):
		print self.status

	def setStatus(self, status):
		self.status = status

	def setHistory_id(self,history_id):
		self.history_id = history_id
