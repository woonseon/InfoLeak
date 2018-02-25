#-*- coding: utf-8 -*-

import sys
reload(sys)  
sys.setdefaultencoding('utf-8')
import struct
import os
import Evtx.Evtx as evtx
import re
import _winreg
import lnk_parser
import pytsk3
import shellbags
import datetime
import calendar
from Registry import Registry

def search(dirname):
	global Glnk
	Glnk = []
	
	filenames = os.listdir(dirname)
	try:
		for filename in filenames:
			full_filename = os.path.join(dirname, filename)
			if os.path.isdir(full_filename):
				search(full_filename)
			else:
				ext = os.path.splitext(full_filename)[-1]
				if ext == '.lnk': 
					out = lnk_parser.parse_lnk(full_filename)
					if(len(out) == 4):
						if(out[2] != '' and out[3] != ''):
							Glnk.append(out)
	except:
		pass

def eventLog():
	global Geventlog
	Geventlog = []

	file = open('./output_evtx.csv', 'w')
	title = "SerialNumber,Event,Time,LifetimeID\n"
	file.write(title)

	args = "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx"
	with evtx.Evtx(args) as log:
		for record in log.records():
			# print(record.xml())
			EventID = re.search('<EventID Qualifiers="">.*</EventID>', record.xml(), re.I|re.S)
			EventID = EventID.group().split('>')[1].split('<')[0]

			if(int(EventID) == 2100):
				Time = re.search('<TimeCreated SystemTime=.*/TimeCreated>', record.xml(), re.I|re.S)
				Time = Time.group().split('\"')[1]
				
				lifeTime = re.search('instance.*\"', record.xml(), re.I|re.S)
				lifeTime = lifeTime.group().split('\"')[3]

				DeviceIdentifier = re.search('instance.*\"', record.xml(), re.I|re.S)
				insTance = DeviceIdentifier.group().split('\"')[1]

				if "USBSTOR" in insTance:
					insTancea = insTance.split('#')[-2].split('&')[0] + "&0"
					tmp_list = []
					# print("Disconnected")
					# print(Time)
					# print(insTancea)
					# print(lifeTime)
					tmp_list.append(str(insTancea))
					tmp_list.append("Disconnected")
					tmp_list.append(str(Time))
					tmp_list.append(str(lifeTime))
					Geventlog.append(tmp_list)

					line = str(insTancea) + "," + "Disconnected" + "," + str(Time) + "," + str(lifeTime) + "\n"
					file.write(line)

				

			elif(int(EventID) == 2003):
				Time = re.search('<TimeCreated SystemTime=.*/TimeCreated>', record.xml(), re.I|re.S)
				Time = Time.group().split('\"')[1]

				lifeTime = re.search('instance.*\"', record.xml(), re.I|re.S)
				lifeTime = lifeTime.group().split('\"')[3]

				DeviceIdentifier = re.search('instance.*\"', record.xml(), re.I|re.S)
				insTance = DeviceIdentifier.group().split('\"')[1]

				if "USBSTOR" in insTance:
					insTancea = insTance.split('#')[-2].split('&')[0] + "&0"
					tmp_list = []
					# print("Connected")
					# print(Time)
					# print(insTancea)
					# print(lifeTime)
					tmp_list.append(str(insTancea))
					tmp_list.append("Connected")
					tmp_list.append(str(Time))
					tmp_list.append(str(lifeTime))
					Geventlog.append(tmp_list)

					line = str(insTancea) + "," + "Connected" + "," + str(Time) + "," + str(lifeTime) + "\n"
					file.write(line)
	file.close()


def regParse():
	global GserialNumber, GvolumeName, GmountDriveName
	GserialNumber = []
	GvolumeName = {}
	GmountDriveName = {}
	# Serial Number, Volume명, 마운트 드라이브
	HKLMReg = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
	usbPath = "SYSTEM\\ControlSet001\\Enum\\USBSTOR"
	usbPath2 = "SYSTEM\\ControlSet002\\Enum\\USBSTOR"

	key = _winreg.OpenKey(HKLMReg, usbPath)
	i=0
	try:
		while True:
			val_key = _winreg.EnumKey(key, i)
			serialNumbkey = usbPath	+ "\\" + val_key
			subKey = _winreg.OpenKey(HKLMReg, serialNumbkey)
			serialNumb = _winreg.EnumKey(subKey, 0)
			# print("serial numb: " + serialNumb)
			GserialNumber.append(serialNumb)
			i = i+1
	except:
		pass
	# print(GserialNumber)

	key = _winreg.OpenKey(HKLMReg, usbPath2)
	i=0
	try:
		while True:
			val_key = _winreg.EnumKey(key, i)
			serialNumbkey = usbPath2 + "\\" + val_key
			subKey = _winreg.OpenKey(HKLMReg, serialNumbkey)
			serialNumb = _winreg.EnumKey(subKey, 0)
			# print("serial numb: " + serialNumb)
			GserialNumber.append(serialNumb)
			i = i+1
	except:
		pass

	volumeNamePath = "SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices"
	key = _winreg.OpenKey(HKLMReg, volumeNamePath)
	i=0
	try:
		while True:
			val_key = _winreg.EnumKey(key, i)
			volumeNamekey = volumeNamePath + "\\" + val_key
			subKey = _winreg.OpenKey(HKLMReg, volumeNamekey)
			if "#" in val_key:
				volumeSerialnumb = val_key.split('#')[-2]
				for sn in GserialNumber:
					if sn == volumeSerialnumb:
						volumeName = _winreg.EnumValue(subKey, i)[1]
						GvolumeName[sn] = volumeName
			i = i+1
	except:
		pass
	# print(GvolumeName)

	mountDrivePath = "SYSTEM\\MountedDevices"
	key = _winreg.OpenKey(HKLMReg, mountDrivePath)
	i=0
	try:
		while True:
			val_key = _winreg.EnumValue(key, i)[1]

			for sn in GserialNumber:
				if "#" in val_key.decode("utf-16"):
					mountSerialnumb = val_key.decode("utf-16").split('#')[-2]
					if sn == mountSerialnumb:
						mountDriveName = _winreg.EnumValue(key, i)[0].split('\\')[-1]
						if "Volume" in mountDriveName:
							pass
						else:
							GmountDriveName[sn] = mountDriveName
			i = i+1
	except:
		pass
	# print(GmountDriveName)


def setupApi():
	global GsetupApi
	GsetupApi = {}
	
	file = open("Registry\\SETUPAPI\\setupapi.dev.log", 'r')
	while True:
		line = file.readline()
		if line:
			if "Device Install (Hardware initiated)" in line:
				if "USBSTOR" in line:
					serialNumb = line.split("\\")[-1]
					if "#" in line:
						serialNumb = serialNumb.split("#")[-2]
					else:
						serialNumb = serialNumb.split(']')[-2]
					
					time_ss = file.readline()
					time_ss = (time_ss.split(" ")[4:][0] + " " + time_ss.split(" ")[4:][1]).split('\n')[0]

					# print(serialNumb)
					# print(time_ss)
					GsetupApi[serialNumb] = time_ss
		else:
			break
	# print GsetupApi

def FileWrite():
	file = open('./output_reg.csv', 'w')
	title = "SerialNumber,VolumeName,MountDriveName,InitialConnectTime\n"
	file.write(title)
	line = ""
	apline = []
	# print Geventlog
	# print GserialNumber
	# print GvolumeName
	# print GmountDriveName
	# print GsetupApi

	for serialnu in GserialNumber:
		if serialnu in GvolumeName:
			line = line + "," + GvolumeName[serialnu]
			apline.append(GvolumeName[serialnu])
			if serialnu in GmountDriveName:
				line = line + "," + GmountDriveName[serialnu]
				apline.append()
			else:
				line = line + "," + ","
		elif serialnu in GmountDriveName:
			line = serialnu + "," + "," + GmountDriveName[serialnu]
			if serialnu in GvolumeName:
				line = line + "," + GvolumeName[serialnu]
		else:
			line = serialnu + "," + ","
	
		if serialnu in GsetupApi:
			line = line + "," + GsetupApi[serialnu] + "\n"
		else:
			line = line + "," + "\n"
		file.write(line)
	file.close()


def getHive(vol):
	img = pytsk3.Img_Info('\\\\.\\'+vol)
	fs_info = pytsk3.FS_Info(img)

	userprofile = os.path.expandvars("%userprofile%")

	ntUser = userprofile + "\\NTUSER.DAT"
	ntUser = ntUser.replace("\\", "/").split(':/')[1]

	usrClass = userprofile + "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat"
	usrClass = usrClass.replace("\\", "/").split(':/')[1]

	ntfile = fs_info.open(ntUser)
	ntfile_name = ntfile.info.name.name.decode('utf-8')
	offset = 0
	if ntfile.info.meta == None:
		pass
	ntfile_size = ntfile.info.meta.size
	buffSize = 1024*1024
	data = open(ntfile_name, 'wb')
	while offset < ntfile_size:
		nt_read = min(buffSize, ntfile_size - offset)
		nt_set = ntfile.read_random(offset,nt_read)
		if not nt_set: break
		data.write(nt_set)
		offset += len(nt_set)

	ntfile = fs_info.open(usrClass)
	ntfile_name = ntfile.info.name.name.decode('utf-8')
	offset = 0
	if ntfile.info.meta == None:
		pass
	ntfile_size = ntfile.info.meta.size
	data = open(ntfile_name, 'wb')
	while offset < ntfile_size:
		nt_read = min(buffSize, ntfile_size - offset)
		nt_set = ntfile.read_random(offset,nt_read)
		if not nt_set: break
		data.write(nt_set)
		offset += len(nt_set)

def shellBag():
	file = open('./output_shellbag.csv', 'w')
	title = "KeyLastWriteTime,Path,Key\n"
	file.write(title)

	# shellbags.print_shellbag_csv("")
	f = "UsrClass.dat"
	registry = Registry.Registry(f)
	parsed_shellbags = shellbags.get_all_shellbags(registry)
	# print(parsed_shellbags)
	# print parsed_shellbags[0]['klwt']

	for psh in parsed_shellbags:
		# print psh['mtime']
		# mtime = psh['mtime']
		# atime = psh['atime']
		# crtime = psh['crtime']
		klwt = psh['klwt']
		fullpath = psh['path']
		regsrc = psh['source']

		file.write(str(klwt))
		file.write(',')
		file.write(str(fullpath))
		file.write(',')
		file.write(str(regsrc))
		file.write('\n')

	# shellbags.print_shellbag_csv("")
	f = "NTUSER.DAT"
	registry = Registry.Registry(f)
	parsed_shellbags = shellbags.get_all_shellbags(registry)
	# print(parsed_shellbags)
	# print parsed_shellbags[0]['klwt']

	for psh in parsed_shellbags:
		# print psh['mtime']
		# mtime = psh['mtime']
		# atime = psh['atime']
		# crtime = psh['crtime']
		klwt = psh['klwt']
		fullpath = psh['path']
		regsrc = psh['source']

		file.write(str(klwt))
		file.write(',')
		file.write(str(fullpath))
		file.write(',')
		file.write(str(regsrc))
		file.write('\n')
	file.close()


def main():
	# EventLog
	try:
		eventLog()
	except:
		print "eventLog Parsing Error"
		pass
	
	# Registry & setupAPI
	try:
		regParse()
		setupApi()
		FileWrite()
	except:
		print "Registry and setupAPI Parsing Error"
		pass

	# LNK
	try:
		search("C:\\Users")
		file = open('./output_lnk.csv', 'w')
		title = "Filename,TargetModifyTime,VolumeSerial,localBasePath\n"
		file.write(title)
		for nu in Glnk:
			file.write(','.join(nu))
			file.write('\n')
		file.close()
	except:
		print "LNK parsing error"
		pass

	# ShellBag
	try:
		getHive("C:")
		shellBag()
	except:
		print "ShellBag parsing Error"
		pass

if __name__ == "__main__":
	main()