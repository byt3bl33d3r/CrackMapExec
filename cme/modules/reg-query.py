#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations


class CMEModule:
    name = "reg-query"
    description = "Performs a registry query on the machine"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.delete = None
        self.type = None
        self.value = None
        self.key = None
        self.path = None

    def options(self, context, module_options):
        """
        PATH    Registry key path to query
        KEY     Registry key value to retrieve
        VALUE   Registry key value to set (only used for modification)
                Will add a new registry key if the registry key does not already exist
        TYPE    Type of registry to modify, add or delete. Default type : REG_SZ.
                Type supported: REG_NONE, REG_SZ, REG_EXPAND_SZ,REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_LINK, REG_MULTI_SZ, REG_QWORD
        DELETE  If set to True, delete a registry key if it does exist
        """
        self.context = context
        self.path = None
        self.key = None
        self.value = None
        self.type = None
        self.delete = False

        if module_options and "PATH" in module_options:
            self.path = module_options["PATH"]

        if module_options and "KEY" in module_options:
            self.key = module_options["KEY"]

        if "VALUE" in module_options:
            self.value = module_options["VALUE"]
            if "TYPE" in module_options:
                type_dict = {
                    "REG_NONE": rrp.REG_NONE,
                    "REG_SZ": rrp.REG_SZ,
                    "REG_EXPAND_SZ": rrp.REG_EXPAND_SZ,
                    "REG_BINARY": rrp.REG_BINARY,
                    "REG_DWORD": rrp.REG_DWORD,
                    "REG_DWORD_BIG_ENDIAN": rrp.REG_DWORD_BIG_ENDIAN,
                    "REG_LINK": rrp.REG_LINK,
                    "REG_MULTI_SZ": rrp.REG_MULTI_SZ,
                    "REG_QWORD": rrp.REG_QWORD,
                }
                self.type = module_options["TYPE"]
                if "WORD" in self.type:
                    try:
                        self.value = int(self.value)
                    except:
                        context.log.fail(f"Invalid registry value type specified: {self.value}")
                        return
                if self.type in type_dict:
                    self.type = type_dict[self.type]
                else:
                    context.log.fail(f"Invalid registry value type specified: {self.type}")
                    return
            else:
                self.type = 1

        if module_options and "DELETE" in module_options and module_options["DELETE"].lower() == "true":
            self.delete = True

    def on_admin_login(self, context, connection):
        self.context = context
        if not self.path:
            self.context.log.fail("Please provide the path of the registry to query")
            return
        if not self.key:
            self.context.log.fail("Please provide the registry key to query")
            return

        remote_ops = RemoteOperations(connection.conn, False)
        remote_ops.enableRegistry()

        try:
            if "HKLM" in self.path or "HKEY_LOCAL_MACHINE" in self.path:
                self.path = self.path.replace("HKLM\\", "")
                ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            elif "HKCU" in self.path or "HKEY_CURRENT_USER" in self.path:
                self.path = self.path.replace("HKCU\\", "")
                ans = rrp.hOpenCurrentUser(remote_ops._RemoteOperations__rrp)
            elif "HKCR" in self.path or "HKEY_CLASSES_ROOT" in self.path:
                self.path = self.path.replace("HKCR\\", "")
                ans = rrp.hOpenClassesRoot(remote_ops._RemoteOperations__rrp)
            else:
                self.context.log.fail(f"Unsupported registry hive specified in path: {self.path}")
                return

            reg_handle = ans["phKey"]
            ans = rrp.hBaseRegOpenKey(remote_ops._RemoteOperations__rrp, reg_handle, self.path)
            key_handle = ans["phkResult"]

            if self.delete:
                # Delete registry
                try:
                    # Check if value exists
                    data_type, reg_value = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, self.key)
                except:
                    self.context.log.fail(f"Registry key {self.key} does not exist")
                    return
                # Delete value
                rrp.hBaseRegDeleteValue(remote_ops._RemoteOperations__rrp, key_handle, self.key)
                self.context.log.success(f"Registry key {self.key} has been deleted successfully")
                rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)

            if self.value is not None:
                # Check if value exists
                try:
                    # Check if value exists
                    data_type, reg_value = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, self.key)
                    self.context.log.highlight(f"Key {self.key} exists with value {reg_value}")
                    # Modification
                    rrp.hBaseRegSetValue(
                        remote_ops._RemoteOperations__rrp,
                        key_handle,
                        self.key,
                        self.type,
                        self.value,
                    )
                    self.context.log.success(f"Key {self.key} has been modified to {self.value}")
                except:
                    rrp.hBaseRegSetValue(
                        remote_ops._RemoteOperations__rrp,
                        key_handle,
                        self.key,
                        self.type,
                        self.value,
                    )
                    self.context.log.success(f"New Key {self.key} has been added with value {self.value}")
                    rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)
            else:
                # Query
                try:
                    data_type, reg_value = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, self.key)
                    self.context.log.highlight(f"{self.key}: {reg_value}")
                except:
                    if self.delete:
                        pass
                    else:
                        self.context.log.fail(f"Registry key {self.key} does not exist")
                        return
            rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)
        except DCERPCException as e:
            self.context.log.fail(f"DCERPC Error while querying or modifying registry: {e}")
        except Exception as e:
            self.context.log.fail(f"Error while querying or modifying registry: {e}")
        finally:
            remote_ops.finish()
