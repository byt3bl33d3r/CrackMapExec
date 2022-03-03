def add_user_bh(user, domain, logger, config):

    if not config.has_option('BloodHound', 'bh_enabled') or config.get('BloodHound', 'bh_enabled') == "False":
        return

    from neo4j.exceptions import AuthError, ServiceUnavailable

    try:
        from neo4j.v1 import GraphDatabase
    except:
        from neo4j import GraphDatabase

    if isinstance(user, str):
        users_owned = [{'username': user.upper(), 'domain': domain.upper()}]
    else:
        users_owned = user

    bh_uri = config.get('Bloodhound', 'bh_uri')
    bh_port = config.get('Bloodhound', 'bh_port')
    bh_user = config.get('Bloodhound', 'bh_user')
    bh_pass = config.get('Bloodhound', 'bh_pass')

    uri = "bolt://{}:{}".format(bh_uri, bh_port)
    driver = GraphDatabase.driver(uri, auth=(bh_user, bh_port), encrypted=False)

    try:
        with driver.session() as session:
            with session.begin_transaction() as tx:

                for info in users_owned:

                    username = info['username']
                    domain = info['domain']

                    if username[-1] == '$':
                        user_owned = "{}.{}".format(username[:-1], domain)
                        account_type = 'Computer'

                    else:
                        user_owned = "{}@{}".format(username, domain)
                        account_type = 'User'

                    result = tx.run( "MATCH (c:{} {{name:\"{}\"}}) RETURN c".format(account_type, user_owned))

                    if result.data()[0]['c'].get('owned') in (False, None):
                        logger.debug("MATCH (c:{} {{name:\"{}\"}}) SET c.owned=True RETURN c.name AS name".format(account_type, user_owned))
                        result = tx.run( "MATCH (c:{} {{name:\"{}\"}}) SET c.owned=True RETURN c.name AS name".format(account_type, user_owned))
                        logger.highlight("Node {} successfully set as owned in BloodHound".format(user_owned))

    except AuthError as e:
        logger.error("Provided Neo4J credentials ({}:{}) are not valid.".format(bh_user, bh_pass))
        return

    except ServiceUnavailable as e:
        logger.error("Neo4J does not seem to be available on {}.".format(uri))
        return

    except Exception as e:
        logger.error("Unexpected error with Neo4J")
        logger.error("Error : ".format(str(e)))
        return

    driver.close()
