#!/usr/bin/env python3

import json
try:
	import binwalk
except:
	os.system("pip3 install binwalk")
	import binwalk
import subprocess
import os

class Firmware():
	def __init__(self,firmware_file):
		self.firmware_file = firmware_file
		self.exf = '_'+self.firmware_file+'.extracted'
		self.analysed_data = {}
		self.results = None
	def extract(self):
		if os.path.isdir(self.exf):
			shutil.rmtree(self.exf) 
		self.results = subprocess.run(['binwalk', '-e',self.firmware_file], stdout=subprocess.PIPE).stdout.decode('utf-8')


	def export_to_json(self):
		json_str = json.dumps(self.analysed_data,indent=4)
		with open("output.json",'w+') as json_file:
			json_file.write(json_str)


if __name__ == "__main__":
	f = Firmware(sys.argv[1])
	f.smartrun()
