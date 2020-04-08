#!/usr/bin/env python3.8
#Software License Agreement (BSD License)
#Copyright (c) 2017 Phil Arkwright nad last update on me
#All rights reserved.

from __future__ import division
from pprint import pprint
from scapy.all import *
import numpy
import configparser
import os.path
import json
import scapy
import tldextract #Seperating subdomain from input_domain in capture 
import alexa

from pushbullet import PushBullet

import argparse

pushbullet_key = ''
if pushbullet_key != '':
	#Configure pushbulet 
	p = PushBullet(pushbullet_key)

	def send_note(note):
		push = p.push_note('%s' % (note), '')

def hasNumbers(inputString):
	return any(char.isdigit() for char in inputString)

def ConfigSectionMap(section):
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print("exception on %s!" % option)
            dict1[option] = None
    return dict1

Config = configparser.ConfigParser()
previous_domain = ''
whitelist = {}

def load_settings():

	if os.path.isfile('settings.conf'):
		Config.read("settings.conf")
		percentage_list_dga_settings = float(ConfigSectionMap("Percentages")['percentage_list_dga_settings'])
		percentage_list_alexa_settings = float(ConfigSectionMap("Percentages")['percentage_list_alexa_settings'])
		baseline = float(ConfigSectionMap("Percentages")['baseline'])
		total_bigrams_settings = float(ConfigSectionMap("Values")['total_bigrams_settings'])
		return baseline, total_bigrams_settings
	else:
		print("No settings file. Please run training function.")

def load_data():

	if os.path.isfile('database.json') and os.path.isfile('settings.conf'):

		baseline, total_bigrams_settings = load_settings()

		with open('database.json', 'r') as f:
		    try:
		        bigram_dict = json.load(f)
		        process_data(bigram_dict, total_bigrams_settings) #Call process_data
		    # if the file is empty the ValueError will be thrown
		    except ValueError:
		        bigram_dict = {}
	else:

		try:
			cfgfile = open("settings.conf",'w')
			Config.add_section('Percentages')
			Config.add_section('Values')
			Config.set('Percentages','baseline', '0')
			Config.write(cfgfile)
			cfgfile.close()
		except:
			print("Settings file error. Please Delete.")
			exit()

		
		if os.path.isfile('data/alexa_top_1m_domain.json'):
			with open('data/alexa_top_1m_domain.json', 'r') as f:
				training_data = json.load(f)
		else:
			print("Downloading Alexa Top 1m Domains...")
			training_data = alexa.top_list(100)
			with open('data/alexa_top_1m_domain.json', 'w') as f:
				json.dump(training_data, f)


		bigram_dict = {} #Define bigram_dict
		total_bigrams = 0 #Set initial total to 0
		for input_domain in range(len(training_data)): #Run through each input_domain in the training list
			input_domain = tldextract.extract(training_data[input_domain][1])
			if len(input_domain.domain) > 5 and "-" not in input_domain.domain:
				print("Processing domain:", input_domain.domain) #Print input_domain number in list
				for  bigram_position in range(len(input_domain.domain) - 1): #Run through each bigram in input_domain
					total_bigrams = total_bigrams + 1 #Increment bigram total
					if input_domain.domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram already exists in dictionary
						bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] = bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] + 1 #Increment dictionary value by 1
					else:
						bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] = 1 #Add bigram to list and set value to 1

		pprint(bigram_dict) #Print bigram list
		with open('data/database.json', 'w') as f:
			json.dump(bigram_dict, f)

		process_data(bigram_dict, total_bigrams) #Call process_data

def process_data(bigram_dict, total_bigrams):

	if os.path.isfile('data/alexa_top_1m_domain.json'):
		with open('data/alexa_top_1m_domain.json', 'r') as f:
			data = json.load(f)

	percentage_list_alexa = [] #Define average_percentage


	for input_domain in range(len(data)): #Run through each input_domain in the data
		input_domain = tldextract.extract(data[input_domain][1])
		if len(input_domain.domain) > 5 and "-" not in input_domain.domain:
			percentage = [] #Clear percentage list
			for  bigram_position in range(len(input_domain.domain) - 1): #Run through each bigram in the data
				if input_domain.domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram is in dictionary 
					percentage.append((bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] / total_bigrams) * 100) #Get bigram dictionary value and convert to percantage
				else:
					percentage.append(0) #Bigram value is 0 as it doesn't exist

			percentage_list_alexa.append(numpy.mean(percentage)) #Add percentage value to list for total average
			print(input_domain.domain, "AP:", numpy.mean(percentage)) #Print input_domain and percentage list


	data = open('data/dga_training.txt').read().splitlines()
	percentage_list_dga = [] #Define average_percentage

	for input_domain in range(len(data)): #Run through each input_domain in the data
		input_domain = tldextract.extract(data[input_domain])
		if len(input_domain.domain) > 5 and "-" not in input_domain.domain:
			percentage = [] #Clear percentage list
			for  bigram_position in range(len(input_domain.domain) - 1): #Run through each bigram in the data
				if input_domain.domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram is in dictionary 
					percentage.append((bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] / total_bigrams) * 100) #Get bigram dictionary value and convert to percantage
				else:
					percentage.append(0) #Bigram value is 0 as it doesn't exist

			percentage_list_dga.append(numpy.mean(percentage)) #Add percentage value to list for total average
			print(input_domain.domain, "AP:", numpy.mean(percentage)) #Print input_domain and percentage list

	print (67 * "*")
	print ("Total Average Percentage Alexa:", numpy.mean(percentage_list_alexa), "( Min:", min(percentage_list_alexa), "Max:", max(percentage_list_alexa), ")") #Get average percentage
	print ("Total Average Percentage DGA:", numpy.mean(percentage_list_dga), "( Min:", min(percentage_list_dga), "Max:", max(percentage_list_dga), ")") #Get average percentage
	print ("Baseline:", (((numpy.mean(percentage_list_alexa) - numpy.mean(percentage_list_dga)) / 2) + numpy.mean(percentage_list_dga)))
	print (67 * "*")

	cfgfile = open("data/settings.conf",'w')
	listas = str(numpy.mean(percentage_list_alexa))
	short =  str(numpy.mean(percentage_list_dga))
	koport = ((numpy.mean(percentage_list_alexa) - numpy.mean(percentage_list_dga)) /2) + numpy.mean(percentage_list_dga)
	nord = str(koport)
	ols = str(total_bigrams)
	Config.set('Percentages','percentage_list_alexa_settings', listas)
	Config.set('Percentages','percentage_list_dga_settings', short)
	Config.set('Percentages','baseline', nord)
	Config.set('Values','total_bigrams_settings', ols)
	Config.write(cfgfile)
	cfgfile.close()

	percentage = [] #Define percentage


def testing():

	baseline, total_bigrams_settings = load_settings()

	if os.path.isfile('data/database.json'):
		with open('data/database.json', 'r') as f:
		    try:
		        bigram_dict = json.load(f)
		    # if the file is empty the ValueError will be thrown
		    except ValueError:
		        bigram_dict = {}


	data = open('data/test_domains.txt').read().splitlines()


	flag = 0
	total_flags = 0
	percentage = [] #Define percentage

	for input_domain in range(len(data)): #Run through each input_domain in the data
		input_domain = tldextract.extract(data[input_domain])
		if len(input_domain.domain) > 5 and "-" not in input_domain.domain:
			for  bigram_position in range(len(input_domain.domain) - 1): #Run through each bigram in the data
				if input_domain.domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram is in dictionary
					percentage.append((round(((bigram_dict[input_domain.domain[bigram_position:bigram_position + 2]] / total_bigrams_settings) * 100), 2))) #Get bigram dictionary value and convert to percantage
				else:
					percentage.append(0) #Bigram value is 0 as it doesn't exist
			

			total_flags = total_flags + 1

			if baseline >= numpy.mean(percentage):
				flag = flag + 1
				print(input_domain.domain, percentage,"AP:", numpy.mean(percentage))
			else:
				print(input_domain.domain, percentage, "AP:", numpy.mean(percentage))


			percentage = [] #Clear percentage list

	print(67 * "*")
	print("Detection Rate:", flag / total_flags * 100)
	print(67 * "*")

def check_domain(input_domain):

	baseline, total_bigrams_settings = load_settings()

	if os.path.isfile('/var/log/named/query.log'):
		with open('/var/log/named/query.log', 'r') as f:
		    try:
		        bigram_dict = json.load(f)
		    # if the file is empty the ValueError will be thrown
		    except ValueError:
		        bigram_dict = {}
	
	percentage = []

	for  bigram_position in range(len(input_domain) - 1): #Run through each bigram in the data
		if input_domain[bigram_position:bigram_position + 2] in bigram_dict: #Check if bigram is in dictionary 
			percentage.append((bigram_dict[input_domain[bigram_position:bigram_position + 2]] / total_bigrams_settings) * 100) #Get bigram dictionary value and convert to percantage
		else:
			percentage.append(0) #Bigram value is 0 as it doesn't exist

	if baseline >= numpy.mean(percentage):
		print(67 * "*")
		print('Baseline:', baseline, 'Domain Average Bigram Percentage:',numpy.mean(percentage))
		return 1
	else:
		return 0

	percentage = [] #Clear percentage list

def capture_traffic(pkt):

	global previous_domain
	global baseline
	global total_bigram_settings
	global previous_domain
	global whitelist

	if IP in pkt:
		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
			prosl = pkt.getlayer(DNS).qd.qname
			prosl = prosl.decode('utf-8')
			input_domain = tldextract.extract(prosl)
			if input_domain.suffix != '' and input_domain.suffix != 'localdomain' and input_domain.subdomain == '' and len(input_domain.domain) > 5 and "-" not in input_domain.domain and previous_domain != input_domain.domain: #Domains are no smaller than 6
				previous_domain = input_domain.domain
				if ("%s.%s" % (input_domain.domain, input_domain.suffix)) not in whitelist.values() and check_domain(input_domain.domain) == 1:
					print('Extracted Domain:', input_domain.domain)
					print(str(ip_src) +  "->",  str(ip_dst), "Warning! Potential DGA Detected ", "(", (pkt.getlayer(DNS).qd.qname), ")")
					print(67 * "*")
					print('\n')
					if pushbullet_key != '':
						alert_message = str((str(ip_src) +  "->",  str(ip_dst), "Warning! Potential DGA Detected ", "(", (pkt.getlayer(DNS).qd.qname), ")"))
						send_note(alert_message)

				#else:
					#print "Safe input_domain", "(" + input_domain + ")"



parser = argparse.ArgumentParser()
parser.add_argument('-o', '--option', required=False)
parser.add_argument('-i', '--interface', required=False)
args = parser.parse_args()

if args.option == '2':
	if os.path.isfile('data/settings.conf'):
		print('Please wait whiles whitelist is read...')
		with open('data/alexa_top_1m_domain.json', 'r') as f:
			whitelist = json.load(f)
		whitelist = dict((k) for k in whitelist)
		###################################
		baseline, total_bigrams_settings = load_settings()
		print('Capturing DNS Requests...')
		sniff(iface = args.interface, filter = "port 53", prn = capture_traffic, store = 0)
		#Using Alexa as a white list (Potentially not the best method incase malware domains make it in the list) More filtering needs to be done.
		#This is in beta and might want to be modified or removed.
	else:
		print(67 * '#')
		print('You must run the training algoirthm first.')
		print(67 * '#')
		exit()


ans=True
while ans:
	print(30 * "-" , "MENU" , 30 * "-")
	print ("""
	1. Train Data
	2. Start Capturing DNS
	3. Testing
	4. View Config File
	5. Delete script data
	6. Exit/Quit
	""")
	print(67 * "-")
	ans = input("Select an option to proceed: ")
	if ans=="1": 
		load_data()
	elif ans=="2":
		if os.path.isfile('data/settings.conf'):
			print('Please wait whiles whitelist is read...')
			with open('data/alexa_top_1m_domain.json', 'r') as f:
				whitelist = json.load(f)
			whitelist = dict((k) for k in whitelist)
			###################################
			baseline, total_bigrams_settings = load_settings()
			try:
				interface = input("[*] Enter Desired Interface: ")
			except KeyboardInterrupt:
				print("[*] User Requested Shutdown...")
				print("[*] Exiting...")
				sys.exit(1)
			sniff(iface = interface,filter = "port 53", prn = capture_traffic, store = 0)
			#Using Alexa as a white list (Potentially not the best method incase malware domains make it in the list) More filtering needs to be done.
			#This is in beta and might want to be modified or removed.
		else:
			print(67 * '#')
			print('You must run the training algoirthm first.')
			print(67 * '#')
			exit()
	elif ans=="3":
		if os.path.isfile('data/settings.conf') and os.path.isfile('data/database.json'):
			testing()
		else:
			print("\nYou must run the training algoirthm first.")
	elif ans=="4":
		if os.path.isfile('data/settings.conf') and os.path.isfile('data/database.json'):
			baseline, total_bigrams_settings = load_settings()
			print(67 * "*")
			print("Total Bigrams:", total_bigrams_settings)
			print("Baseline (Baseline):", baseline)
			print(67 * "*")
		else:
			print("\n No data files available.")
	elif ans=="5":
		if os.path.isfile('data/settings.conf') and os.path.isfile('data/database.json'):
		  os.remove('data/settings.conf')
		  os.remove('data/database.json')
		  print("\nData has been deleted")
		else:
			print("\nNo data to delete.")
	elif ans=="6":
	  print("\nExiting") 
	  quit()
	elif ans !="":
	  print("\n Not Valid Choice Try again") 






