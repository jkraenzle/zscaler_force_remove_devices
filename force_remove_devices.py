import os
from datetime import date
import argparse
import csv
import json
import requests
import logging as log
import logging.handlers

LOG_MSG_FORMAT = '[%(asctime)s] %(levelname)s <pid:%(process)d> %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H-%M-%S'
LOG_LEVELS_TXT = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
LOG_LEVELS_ENUM = [log.DEBUG, log.INFO, log.WARNING, log.ERROR, log.CRITICAL]

def log_namer (log_path):
	base_path_with_base_name = log_path.split('.')[0]
	new_path = base_path_with_base_name + '.' + str(date.today()) + '.log'
	return new_path

def init_logs (log_base_name, log_level_txt, logs_dir=None):

	# Function requirements include validating directory path, setting formatting, rotating, and
	# setting log level
	try:
		# Check that supplied logging directory is valid and can be written
		valid_path = False
		if logs_dir != None:
			# Confirm path exists and can be created
			if os.path.exists(logs_dir) == False:
				os.makedirs(logs_dir)
			valid_path = os.access(logs_dir, os.W_OK)
	except Exception as e:
		raise Exception(f"Unexpected error while initializing logs: {e}")

	# If valid path does not exist, try to default to script directory
	if valid_path == False:
		logs_dir = os.path.dirname(os.path.realpath(__file__))
		if os.access(logs_dir, os.W_OK) == False:
			raise Exception(f"Error: Unable to write to backup log directory '{logs_dir}'")

	try:
		log_name = log_namer(log_base_name)
		log_path = os.path.join(logs_dir, log_name)
		log_level = LOG_LEVELS_ENUM[LOG_LEVELS_TXT.index(log_level_txt)]

		root_log = log.getLogger()
		formatter = log.Formatter(fmt=LOG_MSG_FORMAT, datefmt=LOG_DATE_FORMAT)
		handler = logging.handlers.TimedRotatingFileHandler(log_path, when='midnight', interval=1, backupCount=7)
		handler.namer = log_namer
		handler.setFormatter(formatter)
		handler.setLevel(log_level)
		root_log.addHandler(handler)
		root_log.setLevel(log_level)
	except Exception as e:
		raise Exception(f"Unexpected error while configuring log format: {e}")

	return log_path

class zsMobileAdminApi:
	'''
		A helper class for working with Zscaler's Mobile Admin Portal API.

		See Zscaler's API docs here: https://help.zscaler.com/client-connector/about-zscaler-client-connector-api
	'''
	
	def __init__ (self, zcloud, client_id, client_secret, log=None):

		# Initialize logging for class
		if log == None:
			raise Exception ("Logging subsystem failure")
		else:
			self.log = log
		self.class_name = 'zsMobileAdminApi'
		self.log.info(f"[{self.class_name}] Initializing")

		# Verify ZIA cloud
		if zcloud != None and zcloud not in ['zscaler', 'zscalerone', 'zscalertwo', 'zscalerthree', 'zscalerbeta', 'zscloud']:
			raise Exception("The specified Zscaler Cloud is unknown. "
				+ "Known values are: zscaler, zscalerone, zscalertwo, zscalerthree, zscloud, and zscalerbeta.")

		try:
			# Save credentials
			self.client_id = client_id
			self.client_secret = client_secret

			# Set session values
			self.base_url = f"https://api-mobile.{zcloud}.net/papi"
			self.session = None
			self.jwt_token = None
			self.post_auth_headers = None
		except requests.exceptions.RequestException as e:
			raise SystemExit(e) from None


	def authenticate (self):

		self.log.info(f"[{self.class_name}] Authenticating")

		json = {"apiKey": self.client_id,
			"secretKey": self.client_secret}

		self.session = requests.Session()
		requests.packages.urllib3.disable_warnings()

		try:
			url = self.base_url + "/auth/v1/login"
			headers = {"Content-Type": "application/json", "Accept": "application/json",}

			response = self.session.post(url, headers=headers, json=json, verify=False)

			if response.status_code == 200:
				response_json = response.json()
				self.jwt_token = response_json['jwtToken']
				self.post_auth_headers = {
					"auth-token": self.jwt_token
				}
			else:
				self.log.error("[{self.class_name}] Authentication failed. Check API key and secret.")
				raise SystemExit("Authentication failed") from None

			self.post_auth_headers_json = {"Content-Type": "application/json"} | self.post_auth_headers
			self.post_auth_headers_octetstream = {"Content-Type": "application/octet-stream"} | self.post_auth_headers
 
		except Exception as e:
			self.log.exception(f"[{self.class_name}] " + str(e))
			raise SystemExit(e) from None

	def download_enrolled_devices_as_csv(self):
		try:
			url = self.base_url + "/public/v1/downloadDevices"
			response = self.session.get(url, headers=self.post_auth_headers_octetstream, verify=False)
			if response.status_code == 429:
				self.log.error(f"[{self.class_name}] Quota limit has been reached for /public/v1/downloadDevices API endpoint")
				return None
			elif response.status_code in [200]:
				self.log.info(f"[{self.class_name}] Response from downloadDevices returned successfully.")
				return response.text
			
		except Exception as e:
			self.log.exception(f"[{self.class_name}] " + str(e))


	def get_udids_from_enrolled_devices_csv(self, enrolled_devices_csv, username_filter_list=None, device_filter=None):

		# Check inputs
		# If there is no CSV, return no target UDIDs to remove
		if enrolled_devices_csv == None:
			return []

		# Confirm username input list, or return no target UDIDs to remove
		if username_filter_list == None:
			return []
		else:
			leftover_users = username_filter_list.copy()

		try:
			# Pull in list of dictionaries from downloaded CSV file
			reader = csv.DictReader(enrolled_devices_csv.splitlines(), quoting=csv.QUOTE_ALL, skipinitialspace=True)

			# If username filter is specified in some way, use it to pull UDIDs
			devices_list = []
			if username_filter_list != None:
				for device in reader:
					if 'User' in device:
						device_user = device['User']
						if device_user in username_filter_list:
							try:
								leftover_users.remove(device_user)
							except Exception as e:
								self.log.info(f"[{self.class_name}] User '{device_user}' not found. May have already been removed.")
				
							if 'UDID' in device:
								device_udid = device['UDID']
							else:
								self.log.debug(f"[{self.class_name}] Invalid format for CSV, with no 'UDID' field in device entry.")
								self.log.info(f"[{self.class_name}] No 'UDID' field in device entry. Skipping entry.")
								continue

							if device_filter != None:
								for device in devices_list:
									if device['Hostname'] == device_filter:
										devices_list.append(device_udid)
									else:
										self.log.debug(f"[{self.class_name}] Invalid format for CSV, with no 'Hostname' field in device entry.")
							else:
								devices_list.append(device_udid)
					else:
						self.log.debug(f"[{self.class_name}] Invalid format for CSV, with no 'User' field in device entry.")
				self.log.info(f"[{self.class_name}] Input users without registered devices: {leftover_users}")
				return devices_list
			else:
				return []
		except Exception as e:
			self.log.exception(f"[{self.class_name}] " + str(e))


	def force_remove_devices_by_udids(self, udids):

		page_size = len(udids)
		if page_size == 0:
			self.log.info(f"[{self.class_name}] The list of UDIDs was empty.")
			return

		### If page size > ?, may want to divide the requests into sets of a particular quantity

		try:

			url = self.base_url + f"/public/v1/forceRemoveDevices?pageSize={page_size}"
			payload = {
				"clientConnectorVersion": [],
				"osType": 0,
				"udids": udids,
				"userName": "",
			} 
			response = self.session.post(url, headers=self.post_auth_headers_json, data=json.dumps(payload), verify=False)
			self.log.debug(f"[{self.class_name}] " + str(response))

		except Exception as e:
			self.log.exception(f"[{self.class_name}] " + str(e))

		return

def get_usernames_from_input(log, username_file, username=None):

	if username_file == None:
		if username != None:
			username_list = [username]
		else:
			log.exception(f"[main() arguments] Username filter not specified.")
			raise SystemExit("Invalid arguments. Use --username_file or --username to specify filter.") from None
	else:
		try:
			with open(username_file, "r") as f:
				username_list = [line.strip() for line in f]
		except Exception as e:
			log.exception(f"[{self.class_name}]" + str(e))
			raise SystemExit(e) from None

	return username_list

def test_enrolled_devices_csv():
	response = u'"User","Device type","Device model","External Device ID","UDID","Mac Address","Company Name","OS Version","Zscaler Client Connector Version","Zscaler Digital Experience Version","Policy Name","Last Seen Connected to ZIA","VPN State","Device State","Owner","Hostname","Manufacturer","Config Download Count","Registration TimeStamp","Last Deregistration TimeStamp","Config Download TimeStamp","Keep Alive Timestamp","Device Hardware Fingerprint","Tunnel Version","Log TS","Log Ack TS","Log Url","ZCC Revert Status","Device Trust Level"\n"test2@kraenzle.zscaler.net","MAC","Apple MacBookPro17,1",,"317992DC-577A-5B49-A6E3-B519156BE9AF","3C:06:30:4D:63:FE","Joe Kraenzle-Internal","Version 13.3.1 (Build 22E261) ;arm","3.9.0.81","3.5.0.31","MacOS Tunnel2.0","2023-05-01 00:18:52 GMT","Unknown","Unregistered","jkraenzle","Joseph\xe2\x80\x99s MacBook Pro","Apple","1","2023-04-29 16:13:37 GMT","2023-05-01 00:21:13 GMT","2023-04-29 16:13:37 GMT","2023-05-01 00:18:52 GMT","361c843492f6492548b47d9bdf9454324c19034d","Tunnel 2.0 with DTLS Protocol","","",,"Not Applicable","Not Applicable"\n'
	return response

def main():

	parser = argparse.ArgumentParser(description="Script to force logout users from Client Connector")
	parser.add_argument("--cloud", help="ZIA Cloud (e.g., zscaler, zscloud, zscalerone, ...) for tenant", required=True)
	parser.add_argument("--client_id", help="Zscaler Client Connector API client ID", required=True)
	parser.add_argument("--client_secret", help="Zscaler Client Connector API secret ID", required=True)
	parser.add_argument("--username_file", help="File with list of usernames for bulk logout", required=False)
	parser.add_argument("--username", help="Username for logout", required=False)
	parser.add_argument("--device", help="Device for logout", required=False)
	args = parser.parse_args()
	
	log_path = init_logs('zsMobileAdminApi', 'DEBUG', None)

	mobile_api = zsMobileAdminApi(args.cloud, args.client_id, args.client_secret, log)
	mobile_api.authenticate()

	enrolled_devices_csv = mobile_api.download_enrolled_devices_as_csv()
	#enrolled_devices_csv = test_enrolled_devices_csv()
	username_list = get_usernames_from_input(log, args.username_file, args.username)
	udids = mobile_api.get_udids_from_enrolled_devices_csv(enrolled_devices_csv, username_list, args.device)

	mobile_api.force_remove_devices_by_udids(udids)

	return


if __name__ == "__main__":

	main()
	
