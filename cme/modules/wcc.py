#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pprint import pprint
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5.rrp import DCERPCSessionError
#from impacket.dcerpc.v5.dtypes import RPC_UNICODE_STRING, DWORD, 
from impacket.examples.secretsdump import RemoteOperations
from impacket.system_errors import *
import operator
import time

OUTDATED_THRESHOLD = 30

class CMEModule:
	'''
		Windows Configuration Checker
		Module by @__fpr
	'''
	name = 'wcc'
	description = 'Check various security configuration items on Windows machines'
	supported_protocols = ['smb']
	opsec_safe= True #Does the module touch disk?
	multiple_hosts = True #Does it make sense to run this module on multiple hosts at a time?

	def options(self, context, module_options):
		'''
		OUTPUT_FORMAT   Format for report (Default: 'json')
		OUTPUT          Path for report (Default: './config_checker.json')
		SEP             Separator for registry key path components (Default: '\\')
		VERBOSE         Produce verbose output (Default: False)
		'''
		self.output = module_options.get('OUTPUT', './config_checker.json')
		self.output_format = module_options.get('OUTPUT_FORMAT', 'json')
		self.sep = module_options.get('SEP', '\\')
		self.verbose = 'VERBOSE' in module_options
		self.results = {}

	def debug(self, msg, *args):
		if self.verbose:
			try:
				print(f'\x1b[33m{msg}', *args, '\x1b[0m')
			except BlockingIOError:
				pass

	def on_admin_login(self, context, connection):
		self.log = connection.logger
		self.results.setdefault(connection.host, {'checks':[]})
		remoteOps = RemoteOperations(smbConnection=connection.conn, doKerberos=False)
		remoteOps.enableRegistry()
		dce = remoteOps._RemoteOperations__rrp
		self.check_config(dce, connection)
		#self.check_last_successful_update(connection)
		remoteOps.finish()

	def check_last_successful_update(self, connection):
		records = connection.wmi(wmi_query='Select TimeGenerated FROM Win32_ReliabilityRecords Where EventIdentifier=19', namespace='root\\cimv2')
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


	def add_result(self, host, result):
		self.results[host]['checks'].append({
			"Check":result.name,
			"Description":result.description,
			"Status":'OK' if result.ok else 'KO',
			"Reasons":result.reasons
		})

	def check_config(self, dce, connection):
		host = connection.host
		module = self
		class ConfigCheck:
			"""
			Class for performing the checks and holding the results
			"""
			def __init__(self, name, description=""):
				self.name = name
				self.description = description
				self.ok = False
				self.reasons = []

			def check(self, *specs, op=operator.eq):
				"""
				Perform checks that only require to compare values in the registry with expected values, according to the specs
				a spec may be either a 3-tuple: (key name, value name, expected value), or a 4-tuple (key name, value name, expected value, operation), where operation is a function that implements a comparison operator
				"""
				self.ok = True

				for spec in specs:
					if len(spec) == 3:
						(key, value_name, expected_value) = spec
						op = operator.eq
					elif len(spec) == 4:
						(key, value_name, expected_value, op) = spec
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
						opstring = f'{op.__name__}({{left}}, {{right}}) == True '
						nopstring = f'{op.__name__}({{left}}, {{right}}) == True '

					module.debug('Checking if {0}'.format(opstring.format(left=f'{key}\\{value_name}', right=f'{expected_value}')))
					value = module.reg_query_value(dce, key, value_name)
					module.debug(f'Got value {value}')

					if type(value) == DCERPCSessionError:
						self.ok = False
						if value.error_code in (ERROR_NO_MORE_ITEMS, ERROR_FILE_NOT_FOUND):
							self.reasons.append(f'{key}: Key not found')
						elif value.error_code == ERROR_OBJECT_NOT_FOUND:
							self.reasons.append(f'{value_name}: Value not found')
						continue

					if op(value, expected_value):
						self.reasons.append(opstring.format(left=f'{key}\\{value_name} ({value})', right=expected_value))
					else:
						self.reasons.append(nopstring.format(left=f'{key}\\{value_name} ({value})', right=expected_value))
						self.ok = False

				return self

			def wrap_check(self, check_function, *args, **kwargs):
				"""
				Execute the given check function with the given arguments, and update internal attributes according to the results.
				The check function MUST return a boolean and a list of strings
				"""
				self.ok, self.reasons = check_function(*args, **kwargs)
				return self

			def log(self):
				if self.ok:
					module.log.warning(self.name + ': ' + '\x1b[1;32mOK\x1b[0m')
				else:
					module.log.warning(self.name + ': ' + '\x1b[1;31mKO\x1b[0m')

		# TODO: check_last_successful_update
		# TODO: check_laps
		# TODO: check_administrator_name
		# TODO: check_print_spooler_service
		# TODO: check_wsus
		# TODO: check_applocker
		# TODO: check_powershell_v2_availability
		# TODO: check_nbtns
		# TODO: check_smb_encryption
		# TODO: check_bitlockerconf
		# TODO: check_guest_account
		# TODO: check_execution_policy

		for result in (
			ConfigCheck('Last successful update', 'Checks how old is the last successful update').wrap_check(self.check_last_successful_update, connection),
			ConfigCheck('UAC configuration', 'Checks if UAC configuration is secure').check((
					'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
					'EnableLUA', 1
				),(
					'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
					'LocalAccountTokenFilterPolicy', 0
				)
			),
			ConfigCheck('Hash storage format', 'Checks if storing  hashes in LM format is disabled').check((
					'HKLM\\System\\CurrentControlSet\\Control\\Lsa',
					'NoLMHash', 1
				)
			),
			ConfigCheck('Always install elevated', 'Checks if AlwaysInstallElevated is disabled').check((
					'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer',
					'AlwaysInstallElevated', 0
				)
			),
			ConfigCheck('IPv6 preference', 'Checks if IPv6 is preferred over IPv4').check((
					'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters',
					'DisabledComponents', (32, 255), in_
				)
			),
			ConfigCheck('WDigest authentication', 'Checks if WDigest authentication is disabled').check((
					'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest',
					'UseLogonCredential', 0
				)
			),
			ConfigCheck('LSA cache', 'Checks how many logons are kept in the LSA cache').check((
					'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
					'CachedLogonsCount', 2, le
				)
			),
			ConfigCheck('RDP expiration time', 'Checks RDP session timeout').check((
					'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services',
					'MaxDisconnectionTime', 0, operator.gt
				),(
					'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services',
					'MaxDisconnectionTime', 0, operator.gt
				)
			),
			ConfigCheck('CredentialGuard', 'Checks if CredentialGuard is enabled').check((
					'HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard',
					'EnableVirtualizationBasedSecurity', 1
				),(
					'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
					'LsaCfgFlags', 1
				)
			),
			ConfigCheck('PPL', 'Checks if lsass runs as a protected process').check((
					'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
					'RunAsPPL', 1
				)
			),
			ConfigCheck('PEAP certificate validation', 'Checks if PEAP certificate validation is enabled').check((
					'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Rasman\\PPP\\EAP\\13',
					'ValidateServerCert', 1
				)
			),
			ConfigCheck('NTLMv1', 'Checks if NTLMv1 authentication is disabled').check((
					'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
					'LmCompatibilityLevel', 5, operator.ge
				)
			),
			ConfigCheck('mDNS', 'Checks if mDNS is disabled').check((
					'HKLM\\SYSTEM\\CurrentControlSet\\Services\\DNScache\\Parameters',
					'EnableMDNS', 0
				)
			),
			ConfigCheck('SMB signing', 'Checks if SMB signing is enabled').check((
					'HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters',
					'requiresecuritysignature', 1
				)
			),
			ConfigCheck('LDAP signing', 'Checks if LDAP signing is enabled').check((
					'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters',
					'LDAPServerIntegrity', 2
				),(
					'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS',
					'LdapEnforceChannelBinding', 2
				)
			),
			ConfigCheck('Network selection on lock screen', 'Checks if network selection on lock screen is disabled').check((
					'HKLM\\Software\\Policies\\Microsoft\\Windows\\System',
					'DontDisplayNetworkSelectionUi', 1
				)
			),
			ConfigCheck('Last logged-on user displayed', 'Checks if display of last logged on user is disabled').check((
					'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
					'dontdisplaylastusername', 1
				)
			),
			ConfigCheck('RDP authentication', 'Checks RDP authentication configuration (NLA auth and restricted admin mode)').check((
					'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\',
					'UserAuthentication', 1
				),(
					'HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA',
					'RestrictedAdminMode', 1
				)
			),
			ConfigCheck('Automatic session lock', 'Checks if the session is automatically locked on after a period of inactivity').check((
					'HKCU\\Control Panel\\Desktop',
					'ScreenSaverIsSecure', 1
				),(
					'HKCU\\Control Panel\\Desktop',
					'ScreenSaveTimeOut', 300, le
				)
			),
			ConfigCheck('Legal notice banner', 'Checks if there is a legal notice banner set').check((
					'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
					'legalnoticecaption', "", operator.ne
				)
			)
		):
			result.log()
			self.add_result(host, result)
		pprint(self.results)

	def reg_query_value(self, dce, keyName, valueName=None, separator='\\'):
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

			if value_type in (1, 2, 7):
				value_data = b''.join(value_data).decode('utf-16')
			else:
				value_data = b''.join(value_data)
				if value_type == 4:
					value_data = int.from_bytes(value_data, 'little')
				elif value_type == 5:
					value_data = int.from_bytes(value_data, 'big')
				elif value_type == 11:
					value_data = int.from_bytes(value_data, 'little')
			return value_type, value_name[:-1], value_data

		root_key, subkey = keyName.split(separator, 1)
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
			return None
		root_key_handle = ans['phKey']
		try:
			ans = rrp.hBaseRegOpenKey(dce, root_key_handle, subkey)
		except DCERPCSessionError as e:
			self.debug(e)
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
				self.debug(f'Value {valueName} not found')
				return DCERPCSessionError(error_code=ERROR_OBJECT_NOT_FOUND)

		for handle in (root_key_handle, subkey_handle):
			rrp.hBaseRegCloseKey(dce, handle)

		return data


def le(reg_sz_string, number):
	return int(reg_sz_string[:-1]) <= number

def in_(obj, seq):
	return obj in seq
