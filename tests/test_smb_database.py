#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import os
from time import sleep

import pytest
import pytest_asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from cme.cmedb import create_workspace, delete_workspace
from cme.first_run import first_run_setup
from cme.loaders.protocol_loader import protocol_loader
from cme.logger import setup_logger, CMEAdapter
from cme.paths import WS_PATH
from sqlalchemy.dialects.sqlite import Insert


@pytest.fixture(scope="session")
def event_loop():
    return asyncio.get_event_loop()


@pytest_asyncio.fixture(scope="session")
def db_engine():
    db_path = os.path.join(WS_PATH, "test/smb.db")
    db_engine = create_engine(
        f"sqlite:///{db_path}",
        isolation_level="AUTOCOMMIT",
        future=True
    )
    yield db_engine
    db_engine.dispose()


@pytest_asyncio.fixture(scope="session")
async def db(db_engine):
    proto = "smb"
    setup_logger()
    logger = CMEAdapter()
    first_run_setup(logger)
    p_loader = protocol_loader()
    protocols = p_loader.get_protocols()
    create_workspace("test", p_loader, protocols)

    protocol_db_path = p_loader.get_protocols()[proto]["dbpath"]
    protocol_db_object = getattr(p_loader.load_protocol(protocol_db_path), "database")

    db = protocol_db_object(db_engine)
    yield db
    db.shutdown_db()
    delete_workspace("test")


@pytest_asyncio.fixture(scope="session")
def sess(db_engine):
    session_factory = sessionmaker(
        bind=db_engine,
        expire_on_commit=True
    )

    Session = scoped_session(
        session_factory
    )
    sess = Session()
    yield sess
    sess.close()


@pytest.mark.asyncio
async def test_add_host(db):
    await db.add_host(
        "127.0.0.1",
        "localhost",
        "TEST.DEV",
        "Windows Testing 2023",
        False,
        True,
        True,
        True,
        False,
        False
    )


def test_update_host(db, sess):
    host = {
        "ip": "127.0.0.1",
        "hostname": "localhost",
        "domain": "TEST.DEV",
        "os": "Windows Testing 2023",
        "dc": False,
        "smbv1": True,
        "signing": True,
        "spooler": True,
        "zerologon": False,
        "petitpotam": False
    }
    iq = Insert(db.HostsTable)
    sess.execute(iq, [host])


def test_add_credential():
    pass


def test_update_credential():
    pass


def test_remove_credential():
    pass


def test_add_admin_user():
    pass

def test_get_admin_relations():
    pass

def test_remove_admin_relation():
    pass

def test_is_credential_valid():
    pass

def test_get_credentials():
    pass

def test_get_credential():
    pass

def test_is_credential_local():
    pass

def test_is_host_valid():
    pass

def test_get_hosts():
    pass

def test_is_group_valid():
    pass

def test_add_group():
    pass

def test_get_groups():
    pass

def test_get_group_relations():
    pass

def test_remove_group_relations():
    pass

def test_is_user_valid():
    pass

def test_get_users():
    pass

def test_get_user():
    pass

def test_get_domain_controllers():
    pass

def test_is_share_valid():
    pass

def test_add_share():
    pass

def test_get_shares():
    pass

def test_get_shares_by_access():
    pass

def test_get_users_with_share_access():
    pass

def test_add_domain_backupkey():
    pass

def test_get_domain_backupkey():
    pass

def test_is_dpapi_secret_valid():
    pass

def test_add_dpapi_secrets():
    pass

def test_get_dpapi_secrets():
    pass

def test_add_loggedin_relation():
    pass

def test_get_loggedin_relations():
    pass

def test_remove_loggedin_relations():
    pass

