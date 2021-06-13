#!/usr/bin/env python3

import json
import subprocess
import os
import sys


try:
	import shutil
except:
	os.system("pip3 install shutil")
	import shutil	

try:
	import binwalk
except:
	os.system("pip3 install binwalk")
	import binwalk
try:
	import terminaltables
except:
	os.system("pip3 install terminaltables")
	import terminaltables


class Firmware():
	def __init__(self,firmware_file):
		self.firmware_file = firmware_file
		self.exf = '_'+self.firmware_file+'.extracted'
		self.reset()
		self.results = None


	def reset(self):

		self.analysed_data = {
			"firmware_file":self.firmware_file,
			"image_info":{
							"filesystem_type":None,
							"Architecture":None,
							"OS version":None,
							"Kernel version":None
						},
			"binary_file_list":[]
		}


	def scan_binaries(self):
		tabledata = [['File Name','Type','Permissions','PIE bit','Path']]
		if self.analysed_data["image_info"]["filesystem_type"] == "Squashfs":
			raw_binary_files_list_output = subprocess.run(['scanelf', '-R',f'{self.exf}/squashfs-root'], stdout=subprocess.PIPE).stdout.decode('utf-8')
			binary_files_list = raw_binary_files_list_output.split('\n')
			del binary_files_list[0]

			for i in range(len(binary_files_list)):
				binary_files_list[i] = binary_files_list[i].split()

		for i in range(len(binary_files_list)):
			try:
				name = binary_files_list[i][1].split('/')[-1]
			except:
				continue

			path = binary_files_list[i][1]
			typ = binary_files_list[i][0]
			permissions = subprocess.run(['ls', '-la',path], stdout=subprocess.PIPE).stdout.decode('utf-8').split()[0]
			pie = False
			if 'DYN' in typ:
				piecheck = subprocess.run(['readelf', '-d',path], stdout=subprocess.PIPE).stdout.decode('utf-8')
				if 'DEBUG' in piecheck:
					pie = True

			data = {
				"name":name,
				"path":path,
				"type":typ,
				"permissions":permissions,
				"pie":pie
			}
			tabledata.append([name,typ,permissions,pie,'/'.join(path.split('/')[1:-1])])
			self.analysed_data["binary_file_list"].append(data)
		table = terminaltables.SingleTable(tabledata, 'binary files')
		table.inner_heading_row_border = False
		table.inner_row_border = True
		table.justify_columns = {0: 'center', 1: 'center', 2: 'center',3: 'center',4: 'center'}
		print("\n\n")
		print(table.table)
		print(f"Count : {len(tabledata)-1}")


	def extract(self):
		if os.path.isdir(self.exf):
			shutil.rmtree(self.exf) 
		self.results = subprocess.run(['binwalk', '-e',self.firmware_file], stdout=subprocess.PIPE).stdout.decode('utf-8')

	def run_analysis(self):
		if self.results == None:
			self.results = subprocess.run(['binwalk',self.firmware_file], stdout=subprocess.PIPE).stdout.decode('utf-8')
		info = self.results.split('\n')
		for i in range(len(info)):
			info[i] = info[i].split(',')
			info[i][0] = info[i][0].split()
			for j in range(1,len(info[i])):
				info[i][j] = info[i][j].strip()
		while [['']] in info:
			info.remove([['']])

		while [[]] in info:
			info.remove([[]])
		for i in info:
			if "filesystem" in i[0]:
				self.analysed_data["image_info"]["filesystem_type"] = i[0][i[0].index("filesystem")-1]
				break

		if self.analysed_data["image_info"]["filesystem_type"] == "Squashfs":
			kvfile = info[-1][0][1][2:]
			kvrawoutput = subprocess.run(['binwalk',f'{self.exf}/{kvfile}'], stdout=subprocess.PIPE).stdout.decode('utf-8')
			kvrawoutput = kvrawoutput.split()
			kernel_version = kvrawoutput[kvrawoutput.index('kernel')+2]
			self.analysed_data["image_info"]["kernel version"] = kernel_version
			busyboxloc = f"{self.exf}/squashfs-root/bin/busybox"
			output = subprocess.run(['readelf', '-h',busyboxloc], stdout=subprocess.PIPE).stdout.decode('utf-8')
			output = output.split('\n')
			for i in range(len(output)):
				output[i] = output[i].split()
				if len(output[i]) == 0:
					continue
				elif 'OS' in output[i][0]:
					self.analysed_data["image_info"]["OS version"] = " ".join(output[i][1:])
					os = " ".join(output[i][1:])
					print(f"OS version : {os}")
					print(f"kernel version : {kernel_version}")
				elif 'Machine' in output[i][0]:
					self.analysed_data["image_info"]['Architecture'] = " ".join(output[i][1:])
					arc = " ".join(output[i][1:])
					print(f"Processor Architecture : {arc}")



		

	def export_to_json(self):
		json_str = json.dumps(self.analysed_data,indent=4)
		with open(f"{self.firmware_file}_output.json",'w+') as json_file:
			json_file.write(json_str)

	def process(self):
		self.reset()
		self.extract()
		self.run_analysis()
		self.scan_binaries()
		self.export_to_json()


if __name__ == "__main__":
	f = Firmware(sys.argv[1])
	f.process()

