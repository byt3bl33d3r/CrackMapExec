#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA


class RemoteFile:
    def __init__(
        self,
        smbConnection,
        fileName,
        share="ADMIN$",
        access=FILE_READ_DATA | FILE_WRITE_DATA,
    ):
        self.__smbConnection = smbConnection
        self.__share = share
        self.__access = access
        self.__fileName = fileName
        self.__tid = self.__smbConnection.connectTree(share)
        self.__fid = None
        self.__currentOffset = 0

    def open(self):
        self.__fid = self.__smbConnection.openFile(self.__tid, self.__fileName, desiredAccess=self.__access)

    def seek(self, offset, whence):
        # Implement whence, for now it's always from the beginning of the file
        if whence == 0:
            self.__currentOffset = offset

    def read(self, bytesToRead):
        if bytesToRead > 0:
            data = self.__smbConnection.readFile(self.__tid, self.__fid, self.__currentOffset, bytesToRead)
            self.__currentOffset += len(data)
            return data
        return ""

    def close(self):
        if self.__fid is not None:
            self.__smbConnection.closeFile(self.__tid, self.__fid)
            self.__fid = None

    def delete(self):
        self.__smbConnection.deleteFile(self.__share, self.__fileName)

    def tell(self):
        return self.__currentOffset

    def __str__(self):
        return f"\\\\{self.__smbConnection.getRemoteHost()}\\{self.__share}\\{self.__fileName}"
