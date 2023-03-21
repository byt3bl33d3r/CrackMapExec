#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import os
from time import sleep

from cme.cmedb import CMEDBMenu, create_workspace, create_db_engine, delete_workspace
from cme.first_run import first_run_setup
from cme.loaders.protocol_loader import protocol_loader
from cme.logger import setup_logger, CMEAdapter
from cme.paths import CONFIG_PATH, WS_PATH


class TestSmbDatabase:
    def setup_class(self):
        proto = "smb"
        setup_logger()
        logger = CMEAdapter()
        first_run_setup(logger)
        p_loader = protocol_loader()
        protocols = p_loader.get_protocols()
        create_workspace("test", p_loader, protocols)

        protocol_db_path = p_loader.get_protocols()[proto]["dbpath"]
        protocol_db_object = getattr(p_loader.load_protocol(protocol_db_path), "database")
        db_path = os.path.join(WS_PATH, "test/smb.db")
        db_engine = create_db_engine(db_path)
        self.db = protocol_db_object(db_engine)

    def teardown_class(self):
        asyncio.run(self.db.shutdown_db())
        delete_workspace("test")

    def test_add_host(self):
        print(self.db)
        self.db.add_host(
            "127.0.0.1",
            "localhost",
            "TEST.DEV"
            "Windows Testing 2023",
            True,
            False,
            True,
            False,
            True
        )

    def test_update_host(self):
        pass

    def test_add_credential(self):
        pass

    def test_update_credential(self):
        pass

    def test_remove_credential(self):
        pass

    def test_add_admin_user(self):
        pass

    def test_get_admin_relations(self):
        pass

    def test_remove_admin_relation(self):
        pass

    def test_is_credential_valid(self):
        pass

    def test_get_credentials(self):
        pass

    def test_get_credential(self):
        pass

    def test_is_credential_local(self):
        pass

    def test_is_host_valid(self):
        pass

    def test_get_hosts(self):
        pass

    def test_is_group_valid(self):
        pass

    def test_add_group(self):
        pass

    def test_get_groups(self):
        pass

    def test_get_group_relations(self):
        pass

    def test_remove_group_relations(self):
        pass

    def test_is_user_valid(self):
        pass

    def test_get_users(self):
        pass

    def test_get_user(self):
        pass

    def test_get_domain_controllers(self):
        pass

    def test_is_share_valid(self):
        pass

    def test_add_share(self):
        pass

    def test_get_shares(self):
        pass

    def test_get_shares_by_access(self):
        pass

    def test_get_users_with_share_access(self):
        pass

    def test_add_domain_backupkey(self):
        pass

    def test_get_domain_backupkey(self):
        pass

    def test_is_dpapi_secret_valid(self):
        pass

    def test_add_dpapi_secrets(self):
        pass

    def test_get_dpapi_secrets(self):
        pass

    def test_add_loggedin_relation(self):
        pass

    def test_get_loggedin_relations(self):
        pass

    def test_remove_loggedin_relations(self):
        pass

