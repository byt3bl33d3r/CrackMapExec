#!/usr/bin/env python3
# -*- coding: utf-8 -*-


def add_user_bh(user, domain, logger, config):
    users_owned = []
    if isinstance(user, str):
        users_owned.append({"username": user.upper(), "domain": domain.upper()})
    else:
        users_owned = user
    if config.get("BloodHound", "bh_enabled") != "False":
        try:
            from neo4j.v1 import GraphDatabase
        except:
            from neo4j import GraphDatabase
        from neo4j.exceptions import AuthError, ServiceUnavailable

        uri = f"bolt://{config.get('BloodHound', 'bh_uri')}:{config.get('BloodHound', 'bh_port')}"

        driver = GraphDatabase.driver(
            uri,
            auth=(
                config.get("BloodHound", "bh_user"),
                config.get("BloodHound", "bh_pass"),
            ),
            encrypted=False,
        )
        try:
            with driver.session() as session:
                with session.begin_transaction() as tx:
                    for info in users_owned:
                        if info["username"][-1] == "$":
                            user_owned = info["username"][:-1] + "." + info["domain"]
                            account_type = "Computer"
                        else:
                            user_owned = info["username"] + "@" + info["domain"]
                            account_type = "User"

                        result = tx.run(f'MATCH (c:{account_type} {{name:"{user_owned}"}}) RETURN c')

                        if result.data()[0]["c"].get("owned") in (False, None):
                            logger.debug(f'MATCH (c:{account_type} {{name:"{user_owned}"}}) SET c.owned=True RETURN c.name AS name')
                            result = tx.run(f'MATCH (c:{account_type} {{name:"{user_owned}"}}) SET c.owned=True RETURN c.name AS name')
                            logger.highlight(f"Node {user_owned} successfully set as owned in BloodHound")
        except AuthError as e:
            logger.fail(f"Provided Neo4J credentials ({config.get('BloodHound', 'bh_user')}:{config.get('BloodHound', 'bh_pass')}) are not valid.")
            return
        except ServiceUnavailable as e:
            logger.fail(f"Neo4J does not seem to be available on {uri}.")
            return
        except Exception as e:
            logger.fail("Unexpected error with Neo4J")
            logger.fail("Account not found on the domain")
            return
        driver.close()
