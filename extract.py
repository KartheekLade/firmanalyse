#!/usr/bin/env python3

import json
import binwalk
import subprocess
import os

class Firmware():
	def __init__(self,firmware_file):
		self.firmware_file = firmware_file
		self.exf = '_'+self.firmware_file+'.extracted'
		self.analysed_data = {}
		'''
		#format of output dict
		self.analysed_data = {

			"firmware_file":self.firmware_file,
			"file_size":None,
			"md5":None,
			"image_info":{
				"filesystem_type":None,
				"kernel_version":None,
				"arch":None,
				"vendor_name":None
			},
			"binary_file_list":[
				{
					name:None,
					"version":None,
					"type":None,
					"permissions":None
				}
			]
		}'''

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
	f = Firmware("ax50v1_intel-up-ver1-0-8-P1[20200426-rel65338]_signed.bin")
	f.extact()
