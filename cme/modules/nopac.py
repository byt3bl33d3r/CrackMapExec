# Credit to https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html
# @exploitph @Evi1cg
# module by @mpgn_x64

from binascii import unhexlify
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal

class CMEModule:

    name = 'nopac'
    description = "Check if the DC is vulnerable to CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        '''
        '''     

    def on_login(self, context, connection):

        userName = Principal(connection.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt_with_pac, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, connection.password, connection.domain,
                                                                unhexlify(connection.lmhash), unhexlify(connection.nthash), connection.aesKey,
                                                                connection.host,requestPAC=True)
        context.log.highlight("TGT with PAC size " + str(len(tgt_with_pac)))
        tgt_no_pac, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, connection.password, connection.domain,
                                                                unhexlify(connection.lmhash), unhexlify(connection.nthash), connection.aesKey,
                                                                connection.host,requestPAC=False)
        context.log.highlight("TGT without PAC size " + str(len(tgt_no_pac)))
        if len(tgt_no_pac) < len(tgt_with_pac):
            context.log.highlight("")
            context.log.highlight("VULNEABLE")
            context.log.highlight("Next step: https://github.com/Ridter/noPac")