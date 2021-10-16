# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['./cme/crackmapexec.py'],
             pathex=['./cme'],
             binaries=[],
             datas=[('./cme/protocols', 'cme/protocols'),('./cme/data', 'cme/data'),('./cme/modules', 'cme/modules')],
             hiddenimports=['cme.protocols.mssql.mssqlexec', 'cme.connection', 'impacket.examples.secretsdump', 'impacket.dcerpc.v5.lsat', 'impacket.dcerpc.v5.transport', 'impacket.dcerpc.v5.lsad', 'cme.servers.smb', 'cme.protocols.smb.wmiexec', 'cme.protocols.smb.atexec', 'cme.protocols.smb.smbexec', 'cme.protocols.smb.mmcexec', 'cme.protocols.smb.smbspider', 'cme.protocols.smb.passpol', 'paramiko', 'pypsrp.client', 'pywerview.cli.helpers', 'impacket.tds', 'impacket.version', 'cme.helpers.bash', 'pylnk3', 'lsassy','win32timezone', 'impacket.tds', 'impacket.ldap.ldap', 'impacket.tds'],
             hookspath=['./cme/.hooks'],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='crackmapexec',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True,
          icon='./cme/data/cme.ico' )
