import json


class HostVM:
	name = ''
	ip = ''
	nic = ''

	def __init__(self, name, ip):
		self.name = name
		self.ip = ip

	def displayHostVMInfo(self):
		print "Name : ", self.name,  ", ip: ", self.ip, ", nic:", + self.nic

	def setNic(self, nic):
		self.nic = nic

with open('result.json') as data_file:    
	data = json.load(data_file)
	# Extract Source VM's info
	name = (data['info']['vm1']['name'])
	ip = (data['info']['vm1']['ip'])
	vm1 = HostVM(name, ip)
	vm1.displayHostVMInfo()

	# Extract Source VM's info
	name = (data['info']['vm2']['name'])
	ip = (data['info']['vm2']['ip'])
	vm2 = HostVM(name, ip)
	vm2.displayHostVMInfo()





