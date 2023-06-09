#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import functools
import json
import operator
import time

import cme.logger
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp, samr, scmr
from impacket.dcerpc.v5.rrp import DCERPCSessionError
from impacket.smbconnection import SessionError as SMBSessionError
from impacket.examples.secretsdump import RemoteOperations
from impacket.system_errors import *

# Configuration variables
OUTDATED_THRESHOLD = 30
DEFAULT_OUTPUT_FILE = './wcc_results.json'
DEFAULT_OUTPUT_FORMAT = 'json'
VALID_OUTPUT_FORMATS = ['json', 'csv']

# Registry value types
REG_VALUE_TYPE_UNDEFINED = 0
REG_VALUE_TYPE_UNICODE_STRING = 1
REG_VALUE_TYPE_UNICODE_STRING_WITH_ENV = 2
REG_VALUE_TYPE_BINARY = 3
REG_VALUE_TYPE_32BIT_LE = 4
REG_VALUE_TYPE_32BIT_BE = 5
REG_VALUE_TYPE_UNICODE_STRING_SEQUENCE = 7
REG_VALUE_TYPE_64BIT_LE = 11

# Setup file logger
if 'cme_logger' not in globals():
	cme_logger = cme.logger.setup_logger(log_to_file=True, log_prefix='wcc', logger_name='WCC')

	for handler in cme_logger.handlers:
		if type(handler) != cme.logger.logging.FileHandler:
			cme_logger.removeHandler(handler)
	cme_logger.handlers[0].setFormatter(cme.logger.logging.Formatter('%(asctime)s %(message)s'))

class ConfigCheck:
	"""
	Class for performing the checks and holding the results
	"""

	module = None

	def __init__(self, name, description="", checkers=[None], checker_args=[[]], checker_kwargs=[{}]):
		self.check_id = None
		self.name = name
		self.description = description
		assert len(checkers) == len(checker_args) and len(checkers) == len(checker_kwargs)
		self.checkers = checkers
		self.checker_args = checker_args
		self.checker_kwargs = checker_kwargs
		self.ok = True
		self.reasons = []

	def run(self):
		for checker, args, kwargs in zip(self.checkers, self.checker_args, self.checker_kwargs):
			if checker is None:
				checker = self.module.check_registry
			ok, reasons = checker(*args, **kwargs)
			self.ok = self.ok and ok
			self.reasons.extend(reasons)

	def log(self):
		if self.module.quiet:
			return

		status = '\x1b[1;32mOK\x1b[0m' if self.ok else '\x1b[1;31mKO\x1b[0m'
		reasons = ": " + ', '.join(self.reasons) if self.module.verbose else ''
		msg = f'{status} {self.name}{reasons}'
		kwargs = {'extra':self.module.log.extra}
		msg, kwargs = self.module.log.format(msg, kwargs)
		text = cme.logger.Text.from_ansi(msg)
		cme.logger.cme_console.print(text, **kwargs)

class CMEModule:
	'''
	Windows Configuration Checker
	Module by @__fpr
	'''
	name = 'wcc'
	description = 'Check various security configuration items on Windows machines'
	supported_protocols = ['smb']
	opsec_safe= True
	multiple_hosts = True

	def options(self, context, module_options):
		f'''
		OUTPUT_FORMAT   Format for report (Default: '{DEFAULT_OUTPUT_FORMAT}')
		OUTPUT          Path for report (Default: '{DEFAULT_OUTPUT_FILE}')
		QUIET           Do not print results to stdout (Default: False)
		VERBOSE         Produce verbose output (Default: False)
		'''
		self.output = module_options.get('OUTPUT',DEFAULT_OUTPUT_FILE)
		self.output_format = module_options.get('OUTPUT_FORMAT', DEFAULT_OUTPUT_FORMAT)
		if self.output_format not in VALID_OUTPUT_FORMATS:
			self.output_format = DEFAULT_OUTPUT_FORMAT
		self.verbose = module_options.get('VERBOSE', 'false').lower() in ('true', '1')
		self.quiet = module_options.get('QUIET', 'false').lower() in ('true', '1')

		self.results = {}
		ConfigCheck.module = self
		self.checks_initialized = False

	def on_admin_login(self, context, connection):
		self.log = connection.logger
		self.results.setdefault(connection.host, {'checks':[]})
		remoteOps = RemoteOperations(smbConnection=connection.conn, doKerberos=False)
		remoteOps.enableRegistry()
		dce = remoteOps._RemoteOperations__rrp
		self.check_registry = functools.partial(self.check_registry, dce)

		# Prepare checks
		if not self.checks_initialized:
			self.init_checks(dce, connection)
			self.checks_initialized = True

		self.check_config(dce, connection)
		remoteOps.finish()
		self.export_results()

	def export_results(self):
		with open(self.output, 'w') as output:
			if self.output_format == 'json':
				json.dump(self.results, output)
			elif self.output_format == 'csv':
				output.write('Host,Check,Description,Status,Reasons')
				for host in self.results:
					for result in self.results[host]['checks']:
						output.write(f'\n{host}')
						for field in (result['Check'], result['Description'], result['Status'], ' ; '.join(result['Reasons']).replace('\x00','')):
							if ',' in field:
								field = field.replace('"', '""')
								field = f'"{field}"'
							output.write(f',{field}')
		print(f'\n\x1b[32;1mResults written to {self.output}\x1b[0m')

	def debug(self, msg, *args):
		if self.verbose:
			try:
				print(f'\x1b[33m{msg}', *args, '\x1b[0m')
			except TypeError:
				print('\x1b[33m', repr(msg), *args, '\x1b[0m')
			except Exception as e:
				print(e)

	def add_result(self, host, result):
		self.results[host]['checks'].append({
			"Check":result.name,
			"Description":result.description,
			"Status":'OK' if result.ok else 'KO',
			"Reasons":result.reasons
		})

	# Check methods #
	#################

	def init_checks(self, dce, connection):
		# Declare the checks to do and how to do them
		self.checks = [
			ConfigCheck('Last successful update', 'Checks how old is the last successful update', checkers=[self.check_last_successful_update], checker_args=[[connection]]),
			ConfigCheck('LAPS', 'Checks if LAPS is installed', checkers=[self.check_laps], checker_args=[[dce, connection]]),
			ConfigCheck("Administrator's name", 'Checks if Administror user name has been changed', checkers=[self.check_administrator_name], checker_args=[[connection]]),
			ConfigCheck('UAC configuration', 'Checks if UAC configuration is secure', checker_args=[[(
					'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
					'EnableLUA', 1
				),(
					'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
					'LocalAccountTokenFilterPolicy', 0
				)]]),
			ConfigCheck('Hash storage format', 'Checks if storing  hashes in LM format is disabled', checker_args=[[(
					'HKLM\\System\\CurrentControlSet\\Control\\Lsa',
					'NoLMHash', 1
				)]]),
			ConfigCheck('Always install elevated', 'Checks if AlwaysInstallElevated is disabled', checker_args=[[(
					'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer',
					'AlwaysInstallElevated', 0
				)
			]]),
			ConfigCheck('IPv6 preference', 'Checks if IPv6 is preferred over IPv4', checker_args=[[(
					'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters',
					'DisabledComponents', (32, 255), in_
				)
			]]),
			ConfigCheck('Spooler service', 'Checks if the spooler service is disabled', checkers=[self.check_spooler_service], checker_args=[[connection]]),
			ConfigCheck('WDigest authentication', 'Checks if WDigest authentication is disabled', checker_args=[[(
					'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest',
					'UseLogonCredential', 0
				)
			]]),
			ConfigCheck('WSUS configuration', 'Checks if WSUS configuration uses HTTPS', checkers=[self.check_wsus_running, None], checker_args=[[connection], [(
						'HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate',
						'WUServer', 'https://', startswith
					),(
						'HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate',
						'UseWUServer', 0, operator.eq
					)]], checker_kwargs=[{},{'options':{'lastWins':True}}]),
			ConfigCheck('LSA cache', 'Checks how many logons are kept in the LSA cache', checker_args=[[(
					'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
					'CachedLogonsCount', 2, le
				)
			]]),
			ConfigCheck('AppLocker', 'Checks if there are AppLocker rules defined', checkers=[self.check_applocker], checker_args=[[dce]]),
			ConfigCheck('RDP expiration time', 'Checks RDP session timeout', checker_args=[[(
					'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services',
					'MaxDisconnectionTime', 0, operator.gt
				),(
					'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services',
					'MaxDisconnectionTime', 0, operator.gt
				)
			]]),
			ConfigCheck('CredentialGuard', 'Checks if CredentialGuard is enabled', checker_args=[[(
					'HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard',
					'EnableVirtualizationBasedSecurity', 1
				),(
					'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
					'LsaCfgFlags', 1
				)
			]]),
			ConfigCheck('PPL', 'Checks if lsass runs as a protected process', checker_args=[[(
					'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
					'RunAsPPL', 1
				)
			]]),
			ConfigCheck('PEAP certificate validation', 'Checks if PEAP certificate validation is enabled', checker_args=[[(
					'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Rasman\\PPP\\EAP\\13',
					'ValidateServerCert', 1
				)
			]]),
			ConfigCheck('Powershell v2 availability', 'Checks if powershell v2 is available', checker_args=[[(
					'HKLM\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine',
					'PSCompatibleVersion', '2.0', not_(operator.contains)
				)
			]]),
			ConfigCheck('NTLMv1', 'Checks if NTLMv1 authentication is disabled', checker_args=[[(
					'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
					'LmCompatibilityLevel', 5, operator.ge
				)
			]]),
			ConfigCheck('NBTNS', 'Checks if NBTNS is disabled on all interfaces', checkers=[self.check_nbtns], checker_args=[[dce]]),
			ConfigCheck('mDNS', 'Checks if mDNS is disabled', checker_args=[[(
					'HKLM\\SYSTEM\\CurrentControlSet\\Services\\DNScache\\Parameters',
					'EnableMDNS', 0
				)
			]]),
			ConfigCheck('SMB signing', 'Checks if SMB signing is enabled', checker_args=[[(
					'HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters',
					'requiresecuritysignature', 1
				)
			]]),
			ConfigCheck('LDAP signing', 'Checks if LDAP signing is enabled', checker_args=[[(
					'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters',
					'LDAPServerIntegrity', 2
				),(
					'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS',
					'LdapEnforceChannelBinding', 2
				)
			]]),
			ConfigCheck('SMB encryption', 'Checks if SMB encryption is enabled', checker_args=[[(
					'HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters',
					'EncryptData', 1
				)
			]]),
			ConfigCheck('Network selection on lock screen', 'Checks if network selection on lock screen is disabled', checker_args=[[(
					'HKLM\\Software\\Policies\\Microsoft\\Windows\\System',
					'DontDisplayNetworkSelectionUi', 1
				)
			]]),
			ConfigCheck('Last logged-on user displayed', 'Checks if display of last logged on user is disabled', checker_args=[[(
					'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
					'dontdisplaylastusername', 1
				)
			]]),
			ConfigCheck('RDP authentication', 'Checks RDP authentication configuration (NLA auth and restricted admin mode)', checker_args=[[(
					'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\',
					'UserAuthentication', 1
				),(
					'HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA',
					'RestrictedAdminMode', 1
				)
			]]),
			ConfigCheck('BitLocker configuration', 'Checks the BitLocker configuration (based on https://www.stigviewer.com/stig/windows_10/2020-06-15/finding/V-94859)', checker_args=[[(
					'HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE',
					'UseAdvancedStartup', 1
				),(
					'HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE',
					'UseTPMPIN', 1
				)
			]]),
			ConfigCheck('Guest account disabled', 'Checks if the guest account is disabled', checkers=[self.check_guest_account_disabled], checker_args=[[connection]]),
			ConfigCheck('Automatic session lock', 'Checks if the session is automatically locked on after a period of inactivity', checker_args=[[(
					'HKCU\\Control Panel\\Desktop',
					'ScreenSaverIsSecure', 1
				),(
					'HKCU\\Control Panel\\Desktop',
					'ScreenSaveTimeOut', 300, le
				)
			]]),
			ConfigCheck('Powershell Execution Policy', 'Checks if the Powershell execution policy is set to "Restricted"', checker_args=[[(
					'HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\ShellIds\Microsoft.Powershell',
					'ExecutionPolicy', 'Restricted\x00'
				),(
					'HKCU\\SOFTWARE\\Microsoft\\PowerShell\\1\ShellIds\Microsoft.Powershell',
					'ExecutionPolicy', 'Restricted\x00'
				)
			]], checker_kwargs=[{'options':{'KOIfMissing':False, 'lastWins':True}}]),
			ConfigCheck('Legal notice banner', 'Checks if there is a legal notice banner set', checker_args=[[(
					'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
					'legalnoticecaption', "", operator.ne
				)
			]])
		]

		# Add check to conf_checks table if missing
		db_checks = connection.db.get_checks()
		db_check_names = [ check._asdict()['name'].strip().lower() for check in db_checks ]
		added = []
		for i,check in enumerate(self.checks):
			missing = True
			for db_check in db_checks:
				db_check = db_check._asdict()
				if check.name.strip().lower() == db_check['name'].strip().lower():
					missing = False
					self.checks[i].check_id = db_check['id']
					break

			if missing:
				connection.db.add_check(check.name, check.description)
				added.append(check)

		# Update check_id for checks added to the db
		db_checks = connection.db.get_checks()
		for i,check in enumerate(added):
			check_id = None
			for db_check in db_checks:
				db_check = db_check._asdict()
				if db_check['name'].strip().lower() == check.name.strip().lower():
					check_id = db_check['id']
					break
			added[i].check_id = check_id

	def check_config(self, dce, connection):
		# Get host ID from db
		host_id = None
		hosts = connection.db.get_hosts(connection.host)
		for host in hosts:
			host = host._asdict()
			if host['ip'] == connection.host and host['hostname'] == connection.hostname and host['domain'] == connection.domain:
				host_id = host['id']
				break

		# Perform all the checks and store the results
		for check in self.checks:
			check.run()
			check.log()
			self.add_result(connection.host, check)
			if host_id is not None:
				connection.db.add_check_result(host_id, check.check_id, check.ok, ', '.join(check.reasons).replace('\x00',''))

	def check_registry(self, dce, *specs, options={}):
		"""
		Perform checks that only require to compare values in the registry with expected values, according to the specs
		a spec may be either a 3-tuple: (key name, value name, expected value), or a 4-tuple (key name, value name, expected value, operation), where operation is a function that implements a comparison operator
		"""
		default_options = {
			'lastWins':False,
			'stopOnOK':False,
			'stopOnKO':False,
			'KOIfMissing':True
		}
		default_options.update(options)
		options = default_options
		op = operator.eq
		ok = True
		reasons = []

		for spec in specs:
			if len(spec) == 3:
				(key, value_name, expected_value) = spec
			elif len(spec) == 4:
				(key, value_name, expected_value, op) = spec
			else:
				ok = False
				reasons = ['Check could not be performed (invalid specification provided)']
				return ok, reasons

			if op == operator.eq:
				opstring = '{left} == {right}'
				nopstring = '{left} != {right}'
			elif op == operator.contains:
				opstring = '{left} in {right}'
				nopstring = '{left} not in {right}'
			elif op == operator.gt:
				opstring = '{left} > {right}'
				nopstring = '{left} <= {right}'
			elif op == operator.ge:
				opstring = '{left} >= {right}'
				nopstring = '{left} < {right}'
			elif op == operator.lt:
				opstring = '{left} < {right}'
				nopstring = '{left} >= {right}'
			elif op == operator.le:
				opstring = '{left} <= {right}'
				nopstring = '{left} > {right}'
			elif op == operator.ne:
				opstring = '{left} != {right}'
				nopstring = '{left} == {right}'
			else:
				opstring = f'{op.__name__}({{left}}, {{right}}) == True'
				nopstring = f'{op.__name__}({{left}}, {{right}}) == True'

			value = self.reg_query_value(dce, key, value_name)

			if type(value) == DCERPCSessionError:
				if options['KOIfMissing']:
					ok = False
				if value.error_code in (ERROR_NO_MORE_ITEMS, ERROR_FILE_NOT_FOUND):
					reasons.append(f'{key}: Key not found')
				elif value.error_code == ERROR_OBJECT_NOT_FOUND:
					reasons.append(f'{value_name}: Value not found')
				else:
					ok = False
					reasons.append(f'Error while retrieving value of {key}\\{value_name}: {value}')
				continue

			if op(value, expected_value):
				if options['lastWins']:
					ok = True
				reasons.append(opstring.format(left=f'{key}\\{value_name} ({value})', right=expected_value))
			else:
				reasons.append(nopstring.format(left=f'{key}\\{value_name} ({value})', right=expected_value))
				ok = False
			if ok and options['stopOnOK']:
				break
			if not ok and options['stopOnKO']:
				break

		return ok, reasons

	def check_laps(self, dce, smb):
		key_name = 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPextensions'
		subkeys =  self.reg_get_subkeys(dce, key_name)
		reasons = []
		success = False
		laps_path = '\\Program Files\\LAPS\\CSE'

		for subkey in subkeys:
			value = self.reg_query_value(dce, key_name + '\\' + subkey, 'DllName')
			if type(value) == str and 'laps\\cse\\admpwd.dll' in value.lower():
				reasons.append(f'{key_name}\\...\\DllName matches AdmPwd.dll')
				success = True
				laps_path = '\\'.join(value.split('\\')[1:-1])
				break
		if not success:
			reasons.append(f'No match found in {key_name}\\...\\DllName')

		l = ls(smb, laps_path)
		if l:
			reasons.append('Found LAPS folder at ' + laps_path)
		else:
			success = False
			reasons.append('LAPS folder does not exist')
			return success, reasons


		l = ls(smb, laps_path + '\\AdmPwd.dll')
		if l:
			reasons.append(f'Found {laps_path}\\AdmPwd.dll')
		else:
			success = False
			reasons.append(f'{laps_path}\\AdmPwd.dll not found')

		return success, reasons

	def check_last_successful_update(self, connection):
		records = connection.wmi(wmi_query='Select TimeGenerated FROM Win32_ReliabilityRecords Where EventIdentifier=19', namespace='root\\cimv2')
		if len(records) == 0:
			return False, ['No update found']
		most_recent_update_date = records[0]['TimeGenerated']['value']
		most_recent_update_date = most_recent_update_date.split('.')[0]
		most_recent_update_date = time.strptime(most_recent_update_date, '%Y%m%d%H%M%S')
		most_recent_update_date = time.mktime(most_recent_update_date)
		now = time.time()
		days_since_last_update = (now - most_recent_update_date)//86400
		if days_since_last_update <= OUTDATED_THRESHOLD:
			return True, [f'Last update was {days_since_last_update} <= {OUTDATED_THRESHOLD} days ago']
		else:
			return False, [f'Last update was {days_since_last_update} > {OUTDATED_THRESHOLD} days ago']

	def check_administrator_name(self, connection):
		user_info = self.get_user_info(connection, rid=500)
		name = user_info['UserName']
		ok = name not in ('Administrator', 'Administrateur')
		reasons = [f'Administrator name changed to {name}' if ok else 'Administrator name unchanged']
		return ok, reasons

	def check_guest_account_disabled(self, connection):
		user_info = self.get_user_info(connection, rid=501)
		uac = user_info['UserAccountControl']
		disabled = bool(uac & samr.USER_ACCOUNT_DISABLED)
		reasons = ['Guest account disabled' if disabled else 'Guest account enabled']
		return disabled, reasons

	def check_spooler_service(self, connection):
		ok = False
		service_config, service_status = self.get_service('Spooler', connection)
		if service_config['dwStartType'] == scmr.SERVICE_DISABLED:
			ok = True
			reasons = ['Spooler service disabled']
		else:
			reasons = ['Spooler service enabled']
			if service_status == scmr.SERVICE_RUNNING:
				reasons.append('Spooler service running')
			elif service_status == scmr.SERVICE_STOPPED:
				ok = True
				reasons.append('Spooler service not running')

		return ok, reasons

	def check_wsus_running(self, connection):
		ok = True
		reasons = []
		service_config, service_status = self.get_service('wuauserv', connection)
		if service_config['dwStartType'] == scmr.SERVICE_DISABLED:
			reasons = ['WSUS service disabled']
		elif service_status != scmr.SERVICE_RUNNING:
			reasons = ['WSUS service not running']
		return ok, reasons

	def check_nbtns(self, dce):
		key_name = 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces'
		subkeys = self.reg_get_subkeys(dce, key_name)
		success = False
		reasons = []
		missing = 0
		nbtns_enabled = 0
		for subkey in subkeys:
			value = self.reg_query_value(dce, key_name + '\\' + subkey, 'NetbiosOptions')
			if type(value) == DCERPCSessionError:
				if value.error_code == ERROR_OBJECT_NOT_FOUND:
					missing += 1
				continue
			if value != 2:
				nbtns_enabled += 1
		if missing > 0:
			reasons.append(f'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\<interface>\\NetbiosOption: value not found on {missing} interfaces')
		if nbtns_enabled > 0:
			reasons.append(f'NBTNS enabled on {nbtns_enabled} interfaces out of {len(subkeys)}')
		if missing == 0 and nbtns_enabled == 0:
			success = True
			reasons.append('NBTNS disabled on all interfaces')
		return success, reasons

	def check_applocker(self, dce):
		key_name = 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2'
		subkeys = self.reg_get_subkeys(dce, key_name)
		rule_count = 0
		for collection in subkeys:
			collection_key_name = key_name + '\\' + collection
			rules = self.reg_get_subkeys(dce, collection_key_name)
			rule_count += len(rules)
		success = rule_count > 0
		reasons = [f'Found {rule_count} AppLocker rules defined']

		return success, reasons

	# Methods for getting values from the remote registry #
	#######################################################

	def _open_root_key(self, dce, root_key):
		ans = None
		if root_key.upper() == 'HKLM':
			ans = rrp.hOpenLocalMachine(dce)
		elif root_key.upper() == 'HKCR':
			ans = rrp.hOpenClassesRoot(dce)
		elif root_key.upper() == 'HKU':
			ans = rrp.hOpenUsers(dce)
		elif root_key.upper() == 'HKCU':
			ans = rrp.hOpenCurrentUser(dce)
		elif root_key.upper() == 'HKCC':
			ans = rrp.hOpenCurrentConfig(dce)
		else:
			self.log.error('Invalid root key. Must be one of HKCR, HKCC, HKCU, HKLM or HKU')
		return ans

	def reg_get_subkeys(self, dce, key_name):
		root_key, subkey = key_name.split('\\', 1)
		ans = self._open_root_key(dce, root_key)
		subkeys = []
		if ans is None:
			return ans

		root_key_handle = ans['phKey']
		try:
			ans = rrp.hBaseRegOpenKey(dce, root_key_handle, subkey)
		except DCERPCSessionError as e:
			if e.error_code != ERROR_FILE_NOT_FOUND:
				cme_logger.error(f'Could not retrieve subkey {subkey}: {e}\n')
			return subkeys

		subkey_handle = ans['phkResult']
		i = 0
		while True:
			try:
				ans = rrp.hBaseRegEnumKey(dce=dce, hKey=subkey_handle, dwIndex=i)
				subkeys.append(ans['lpNameOut'][:-1])
				i += 1
			except DCERPCSessionError as e:
				break
		return subkeys

	def reg_query_value(self, dce, keyName, valueName=None):
		"""
		Query remote registry data for a given registry value
		"""
		def subkey_values(subkey_handle):
			dwIndex = 0
			while True:
				try:
					value_type, value_name, value_data = get_value(subkey_handle, dwIndex)
					yield (value_type, value_name, value_data)
					dwIndex += 1
				except DCERPCSessionError as e:
					if e.error_code == ERROR_NO_MORE_ITEMS:
						break
					else:
						self.log.error(f'Received error code {e.error_code}')
						return

		def get_value(subkey_handle, dwIndex=0):
			ans = rrp.hBaseRegEnumValue(dce=dce, hKey=subkey_handle, dwIndex=dwIndex)
			value_type = ans['lpType']
			value_name = ans['lpValueNameOut']
			value_data = ans['lpData']

			# Do any conversion necessary depending on the registry value type
			if value_type in (
				REG_VALUE_TYPE_UNICODE_STRING,
				REG_VALUE_TYPE_UNICODE_STRING_WITH_ENV,
				REG_VALUE_TYPE_UNICODE_STRING_SEQUENCE):
				value_data = b''.join(value_data).decode('utf-16')
			else:
				value_data = b''.join(value_data)
				if value_type in (
					REG_VALUE_TYPE_32BIT_LE,
					REG_VALUE_TYPE_64BIT_LE):
					value_data = int.from_bytes(value_data, 'little')
				elif value_type == REG_VALUE_TYPE_32BIT_BE:
					value_data = int.from_bytes(value_data, 'big')

			return value_type, value_name[:-1], value_data

		root_key, subkey = keyName.split('\\', 1)
		ans = self._open_root_key(dce, root_key)
		if ans is None:
			return ans

		root_key_handle = ans['phKey']
		try:
			ans = rrp.hBaseRegOpenKey(dce, root_key_handle, subkey)
		except DCERPCSessionError as e:
			if e.error_code == ERROR_FILE_NOT_FOUND:
				return e

		subkey_handle = ans['phkResult']

		if valueName is None:
			_,_, data = get_value(subkey_handle)
		else:
			found = False
			for _,name,data in subkey_values(subkey_handle):
				if name.upper() == valueName.upper():
					found = True
					break
			if not found:
				return DCERPCSessionError(error_code=ERROR_OBJECT_NOT_FOUND)

		for handle in (root_key_handle, subkey_handle):
			rrp.hBaseRegCloseKey(dce, handle)

		return data

	# Methods for getting values from SAMR and SCM #
	################################################

	def get_service(self, service_name, connection):
		"""
		Get the service status and configuration for specified service
		"""
		remoteOps = RemoteOperations(smbConnection=connection.conn, doKerberos=False)
		machine_name,_ = remoteOps.getMachineNameAndDomain()
		remoteOps._RemoteOperations__connectSvcCtl()
		dce = remoteOps._RemoteOperations__scmr
		scm_handle = scmr.hROpenSCManagerW(dce, machine_name)['lpScHandle']
		service_handle = scmr.hROpenServiceW(dce, scm_handle, service_name)['lpServiceHandle']
		service_config = scmr.hRQueryServiceConfigW(dce, service_handle)['lpServiceConfig']
		service_status = scmr.hRQueryServiceStatus(dce, service_handle)['lpServiceStatus']['dwCurrentState']
		remoteOps.finish()

		return service_config, service_status

	def get_user_info(self, connection, rid=501):
		"""
		Get user information for the user with the specified RID
		"""
		remoteOps = RemoteOperations(smbConnection=connection.conn, doKerberos=False)
		machine_name, domain_name = remoteOps.getMachineNameAndDomain()

		try:
			remoteOps.connectSamr(machine_name)
		except samr.DCERPCSessionError:
			# If connecting to machine_name didn't work, it's probably because
			# we're dealing with a domain controller, so we need to use the
			# actual domain name instead of the machine name, because DCs don't
			# use the SAM
			remoteOps.connectSamr(domain_name)

		dce = remoteOps._RemoteOperations__samr
		domain_handle = remoteOps._RemoteOperations__domainHandle
		user_handle = samr.hSamrOpenUser(dce, domain_handle, userId=rid)['UserHandle']
		user_info = samr.hSamrQueryInformationUser2(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)
		user_info = user_info['Buffer']['All']
		remoteOps.finish()
		return user_info

def ls(smb, path='\\', share='C$'):
	l = []
	try:
		l = smb.conn.listPath(share, path)
	except SMBSessionError as e:
		if e.getErrorString()[0] == 'STATUS_NO_SUCH_FILE':
			pass
		else:
			cme_logger.error(f'C:\\{path} {e.getErrorString()}\n')
	return l

# Comparison operators #
########################

def le(reg_sz_string, number):
	return int(reg_sz_string[:-1]) <= number

def in_(obj, seq):
	return obj in seq

def startswith(string, start):
	return string.startswith(start)

def not_(boolean_operator):
	def wrapper(*args, **kwargs):
		return not boolean_operator(*args, **kwargs)
	wrapper.__name__ = f'not_{boolean_operator.__name__}'
	return wrapper
