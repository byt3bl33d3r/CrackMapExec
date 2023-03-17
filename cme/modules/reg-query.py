#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations


class CMEModule:
    name = 'reg-query'
    description = 'Performs a registry query on the machine'
    supported_protocols = ['smb']
    opsec_safe = True 
    multiple_hosts = True 

    def options(self, context, module_options):
        '''
        PATH:  Registry key path to query
        KEY:   Registry key value to retrieve
        VALUE  Registry key value to set (only used for modification). Will add a new regitry key if use on registry key that does not already exist
        TYPE   Type of registry to modify, add or delete. Default type : REG_SZ. Type supported : REG_NONE, REG_SZ, REG_EXPAND_SZ,REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_LINK, REG_MULTI_SZ, REG_QWORD
        DELETE    If set to True, delete a registry key if it does exist
        '''

        self.context = context
        self.path = None
        self.key = None
        self.value = None
        self.type = None
        self.delete = False

        if module_options and 'PATH' in module_options:
            self.path = module_options['PATH']

        if module_options and 'KEY' in module_options:
            self.key = module_options['KEY']

        if 'VALUE' in module_options:
            self.value = module_options['VALUE']
            if 'TYPE' in module_options:
                type_dict = {
                    'REG_NONE': rrp.REG_NONE,
                    'REG_SZ': rrp.REG_SZ,
                    'REG_EXPAND_SZ': rrp.REG_EXPAND_SZ,
                    'REG_BINARY': rrp.REG_BINARY,
                    'REG_DWORD': rrp.REG_DWORD,
                    'REG_DWORD_BIG_ENDIAN': rrp.REG_DWORD_BIG_ENDIAN,
                    'REG_LINK': rrp.REG_LINK,
                    'REG_MULTI_SZ': rrp.REG_MULTI_SZ,
                    'REG_QWORD': rrp.REG_QWORD
                }
                self.type = module_options['TYPE']
                if "WORD" in self.type:
                    try :
                        self.value = int(self.value)
                    except:
                        context.log.error("Invalid registry value type specified: %s" % self.value)
                        sys.exit(1)
                if self.type in type_dict:
                    self.type = type_dict[self.type]
                else:
                    context.log.error("Invalid registry value type specified: %s" % self.type)
                    return
            else:
                self.type = 1
            
        if module_options and 'DELETE' in module_options and module_options['DELETE'].lower() == 'true':
            self.delete = True

    def on_admin_login(self, context, connection):
        if not self.path:
            context.log.error("Please provide the path of the registry to query")
            return

        if not self.key:
            context.log.error("Please provide the registry key to query")
            return

        remoteOps = RemoteOperations(connection.conn, False)
        remoteOps.enableRegistry()
                
        try:
            if "HKLM" in self.path or "HKEY_LOCAL_MACHINE" in self.path:
                self.path = (self.path).replace('HKLM\\', '')
                ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)

            elif "HKCU" in self.path or "HKEY_CURRENT_USER" in self.path:
                self.path = (self.path).replace('HKCU\\', '')
                ans = rrp.hOpenCurrentUser(remoteOps._RemoteOperations__rrp)

            elif "HKCR" in self.path or "HKEY_CLASSES_ROOT" in self.path:
                self.path = (self.path).replace('HKCR\\', '')
                ans = rrp.hOpenClassesRoot(remoteOps._RemoteOperations__rrp)

            else:
                context.log.error("Unsupported registry hive specified in path: %s" % self.path)
                return
            
            regHandle = ans['phKey']
            ans = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, self.path)
            keyHandle = ans['phkResult']

            if self.delete:
                # Delete registry
                try:
                    # Check if value exists
                    dataType, reg_value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, self.key)
                except:
                    self.context.log.error("Registry key %s does not exist" % (self.key))
                    return
                # Delete value
                rrp.hBaseRegDeleteValue(remoteOps._RemoteOperations__rrp, keyHandle, self.key)
                self.context.log.success('Registry key %s has been deleted successfully' % (self.key))
                rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)

            if self.value is not None:
                # Check if value exists
                try:
                    # Check if value exists
                    dataType, reg_value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, self.key)
                    self.context.log.highlight("Key %s exists with value %s" % (self.key, reg_value))
                    # Modification
                    rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, self.key, self.type, self.value)
                    context.log.success("Key %s has been modified to %s" % (self.key, self.value))
                except:
                    rrp.hBaseRegSetValue(remoteOps._RemoteOperations__rrp, keyHandle, self.key, self.type, self.value)
                    self.context.log.success("New Key %s has been added with value %s" % (self.key, self.value))
                    rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
                    
            else:
                # Query
                try :
                    dataType, reg_value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, self.key)
                    context.log.highlight("%s: %s" % (self.key, reg_value))
                except:
                    if self.delete:
                        pass
                    else :
                        self.context.log.error("Registry key %s does not exist" % (self.key))
                        return
            rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)

        except DCERPCException as e:
            #context.log.error("DCERPC Error while querying or modifying registry: %s" % e)
            pass
        except Exception as e:
            context.log.error("Error while querying or modifying registry: %s" % e)
            
        finally:
            remoteOps.finish()
