# -*- coding: utf-8 -*-

# Copyright 2017 Slipeer <Slipeer@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging


try:
    import ldap3
    import ldap3.core.exceptions

    # ldap3 v2 changed ldap3.AUTH_SIMPLE -> ldap3.SIMPLE
    try:
        LDAP_AUTH_SIMPLE = ldap3.AUTH_SIMPLE
    except AttributeError:
        LDAP_AUTH_SIMPLE = ldap3.SIMPLE
except ImportError:
    ldap3 = None
    pass

# Config example
# [ldap]
# uri = ldap://example.com:389/
# startls =  false
# base = dc=example,dc=com
# mail_attr = mail
# id_attr = samAccountName
# # if hs_name empty we assume that id_attr contain users matrix id
# # othercase we generate matrix id as @id_attr:hs_name
# hs_name = example.com
# bind_dn = cn=manager,cn=Users,dc=example,dc=com
# bind_pw = some_secret
# filter = (&(objectClass=user)(objectCategory=person))


logger = logging.getLogger(__name__)


class LDAPDatabase:
    def __init__(self, syd):
        if not ldap3:
            logger.info(
                "Missing ldap3 library."
                "This is required for LDAP integration"
            )
            return

        self.sydent = syd

        self.ldap_uri = self.sydent.cfg.get("ldap", "uri")
        self.start_tls = self.sydent.cfg.get("ldap", "startls")
        self.base = self.sydent.cfg.get("ldap", "base")
        try:
            self.email = self.sydent.cfg.get("ldap", "email")
        except:
            self.email = None
        try:
            self.msisdn = self.sydent.cfg.get("ldap", "msisdn")
        except:
            self.msisdn = None
        self.id_attr = self.sydent.cfg.get(
            "ldap", "id_attr"
        ).replace('"', '').replace("'", "")
        self.hs_name = self.sydent.cfg.get(
            "ldap", "hs_name"
        ).replace('"', '').replace("'", "")
        self.bind_dn = self.sydent.cfg.get("ldap", "bind_dn")
        self.bind_pw = self.sydent.cfg.get("ldap", "bind_pw")
        self.ldap_filter = self.sydent.cfg.get(
            "ldap", "filter"
        ).replace('"', '').replace("'", "")

    def HasLdapConfiguration(self):
        if hasattr(self, 'ldap_uri'):
            logger.info("Exists LDAP configuration.")
            return True
        else:
            # No configuration
            return False

    def getMxid(self, medium, address):
        if hasattr(self, medium):
            searchAttr = getattr(self, medium)
        else:
            logger.warning(
                "Unsupported or unconfigured 3pid medium: %r",
                medium
            )
            return None
        if not searchAttr:
            return None
        try:
            server = ldap3.Server(
                host=self.ldap_uri.lower(),
                get_info=None
            )
            logger.debug(
                "Attempting LDAP connection with %s",
                self.ldap_uri
            )
            conn = ldap3.Connection(
                server,
                user=self.bind_dn,
                password=self.bind_pw,
                auto_bind='NONE'
            )
            if (not conn):
                logger.debug("Can't connect to %s", self.ldap_uri)
                return None
            if self.start_tls:
                conn.open
                conn.start_tls
            if (conn.bind()):
                logger.debug("LDAP bind succefull as %s", self.bind_dn)
            else:
                logger.debug(
                    "LDAP bind as %s error: %s",
                    self.bind_dn,
                    conn.result['description']
                )
            conn.search(
                search_base=self.base,
                search_filter="(&(" + searchAttr + "=" + address + ")"
                + self.ldap_filter + ")",
                attributes=[self.id_attr, searchAttr]
            )
            responses = [
                response
                for response
                in conn.response
                if response['type'] == 'searchResEntry'
            ]

            logger.debug(
                "LDAP return %d records for filter: %s",
                len(responses),
                "(&(" + searchAttr + "=" + address + ")"
                + self.ldap_filter + ")"
            )

            if len(responses) == 1:
                logger.debug(
                    "LDAP found one record with %s = %s",
                    searchAttr,
                    address
                )
                # if hs_name empty we assume that id_attr contain user
                # matrix id othercase we generate matrix id
                # as @id_attr:hs_name
                if (self.hs_name):
                    mxid = "@" + responses[0]['attributes'][self.id_attr][0] \
                        + ":" + self.hs_name
                else:
                    mxid = responses[0]['attributes'][self.id_attr][0]
                conn.unbind
                return (medium, address, mxid.lower())

            conn.unbind
            return None

        except ldap3.core.exceptions.LDAPException as e:
            logger.error("Error during LDAP operation: %r", e)
            return None
