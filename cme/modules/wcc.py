#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pprint import pprint
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5.rrp import DCERPCSessionError
#from impacket.dcerpc.v5.dtypes import RPC_UNICODE_STRING, DWORD, 
from impacket.examples.secretsdump import RemoteOperations
from impacket.system_errors import *

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
			print(f'\x1b[33m{msg}', *args, '\x1b[0m')

	def on_login(self, context, connection):
		self.log = connection.logger
		self.results.setdefault(connection.host, {'checks':[]})
		remoteOps = RemoteOperations(smbConnection=connection.conn, doKerberos=False)
		remoteOps.enableRegistry()
		dce = remoteOps._RemoteOperations__rrp
		#pprint(vars(connection))
		self.check_config(dce, connection.host)
		#print(self.reg_query_value(dce, 'HKCU\\Volatile Environment', valueName='USERNAME', separator=self.sep))
		#self.reg_query_value(dce, 'HKCT\\System\\GameConfigStore', valueName=None, separator=self.sep)
		remoteOps.finish()

	def add_result(self, host, result):
		self.results[host]['checks'].append({
			"Check":result.name,
			"Description":result.description,
			"Status":'OK' if result.ok else 'KO',
			"Reasons":result.reasons
		})

	def check_config(self, dce, host):
		module = self
		class ConfigCheck:
			"""
			Class for doing the simple checks that only require checking registry values
			"""
			def __init__(self, name, description=""):
				self.name = name
				self.description = description
				self.ok = False
				self.reasons = []

			def check(self, *specs):
				self.ok = True
				for (key, value_name, expected_values) in specs:
					module.debug(f'Checking if {key}\\{value_name} == {expected_values}')
					value = module.reg_query_value(dce, key, value_name)
					module.debug(f'Got value {value}')
					if type(value) == DCERPCSessionError:
						self.ok = False
						if value.error_code in (ERROR_NO_MORE_ITEMS, ERROR_FILE_NOT_FOUND):
							self.reasons.append(f'{key}: Key not found')
						elif value.error_code == ERROR_OBJECT_NOT_FOUND:
							self.reasons.append(f'{value_name}: Value not found')
						continue

					try:
						iter(expected_values)
					except TypeError:
						if value == expected_values:
							self.reasons.append(f'{value_name} == {value}')
						else:
							self.reasons.append(f'{value_name} ({value}) != {expected_values}')
							self.ok = False
					else:
						if value in expected_values:
							self.reasons.append(f'{value_name} == {value}')
						else:
							self.reasons.append(f'{value_name} not in {expected_values}')
							self.ok = False
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
		# TODO: check_lsa_cache
		# TODO: check_applocker
		# TODO: check_rdp_expiration_time
		# TODO: check_powershell_v2_availability
		# TODO: check_ntlmv1
		# TODO: check_nbtns
		# TODO: check_bitlockerconf
		# TODO: check_guest_account
		# TODO: check_session_lock
		# TODO: check_legal_notice

		for result in (
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
					'DisabledComponents', (32, 255)
				)
			),
			ConfigCheck('WDigest authentication', 'Checks if WDigest authentication is disabled').check((
					'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest',
					'UseLogonCredential', 0
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


