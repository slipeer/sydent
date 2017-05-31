# -*- coding: utf-8 -*-

# Copyright 2014,2017 OpenMarket Ltd
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

from sydent.util import time_msec

from sydent.threepid import ThreepidAssociation, threePidAssocFromDict
from sydent.db.invite_tokens import JoinTokenStore
from sydent.threepid.assocsigner import AssociationSigner
import signedjson.sign

import json
import logging

logger = logging.getLogger(__name__)

class LocalAssociationStore:
    def __init__(self, sydent):
        self.sydent = sydent

    def addOrUpdateAssociation(self, assoc):
        cur = self.sydent.db.cursor()

        # sqlite's support for upserts is atrocious
        cur.execute("insert or replace into local_threepid_associations "
                    "('medium', 'address', 'mxid', 'ts', 'notBefore', 'notAfter')"
                    " values (?, ?, ?, ?, ?, ?)",
                    (assoc.medium, assoc.address, assoc.mxid, assoc.ts, assoc.not_before, assoc.not_after))
        self.sydent.db.commit()

    def getAssociationsAfterId(self, afterId, limit):
        cur = self.sydent.db.cursor()

        if afterId is None:
            afterId = -1

        q = "select id, medium, address, mxid, ts, notBefore, notAfter from local_threepid_associations " \
            "where id > ? order by id asc"
        if limit is not None:
            q += " limit ?"
            res = cur.execute(q, (afterId, limit))
        else:
            # No no, no no no no, no no no no, no no, there's no limit.
            res = cur.execute(q, (afterId,))

        maxId = None

        assocs = {}
        for row in res.fetchall():
            assoc = ThreepidAssociation(row[1], row[2], row[3], row[4], row[5], row[6])
            assocs[row[0]] = assoc
            maxId = row[0]

        return (assocs, maxId)


class GlobalAssociationStore:
    def __init__(self, sydent):
        self.sydent = sydent

    def signedAssociationStringForThreepid(self, medium, address):
        if self.sydent.ldap.HasLdapConfiguration():
            res = self.sydent.ldap.getMxid(medium, address)
            if res:
                # Create or update assotiation!
                mxid = res[2]
                logger.info("Found mxid %r", mxid)
                localAssocStore = LocalAssociationStore(self.sydent)
                createdAt = time_msec()
                expires = createdAt + 100 * 365 * 24 * 60 * 60 * 1000
                assoc = ThreepidAssociation(medium, address, mxid, createdAt, createdAt, expires)
                localAssocStore.addOrUpdateAssociation(assoc)
                self.sydent.pusher.doLocalPush()

                joinTokenStore = JoinTokenStore(self.sydent)
                pendingJoinTokens = joinTokenStore.getTokens(medium, address)
                invites = []
                for token in pendingJoinTokens:
                    token["mxid"] = mxid
                    token["signed"] = {
                        "mxid": mxid,
                        "token": token["token"],
                    }
                    token["signed"] = signedjson.sign.sign_json(token["signed"], self.sydent.server_name, self.sydent.keyring.ed25519)
                    invites.append(token)
                if invites:
                    assoc.extra_fields["invites"] = invites
                    joinTokenStore.markTokensAsSent(medium, address)

                assocSigner = AssociationSigner(self.sydent)
                sgassoc = assocSigner.signedThreePidAssociation(assoc)
                logger.info("Updated assoc %r", sgassoc)
                return json.dumps(sgassoc)
        else:
            # Search all in database
            cur = self.sydent.db.cursor()
            # We treat address as case-insensitive because that's true for all the threepids
            # we have currently (we treat the local part of email addresses as case insensitive
            # which is technically incorrect). If we someday get a case-sensitive threepid,
            # this can change.
            res = cur.execute("select sgAssoc from global_threepid_associations where "
                        "medium = ? and lower(address) = lower(?) and notBefore < ? and notAfter > ? "
                        "order by ts desc limit 1",
                        (medium, address, time_msec(), time_msec()))
            row = res.fetchone()
            if not row:
                return None
            sgAssocBytes = row[0]
            return sgAssocBytes




    def getMxid(self, medium, address):
        if self.sydent.ldap.HasLdapConfiguration():
            res = self.sydent.ldap.getMxid(medium, address)
            if res:
                    return res

        cur = self.sydent.db.cursor()
        res = cur.execute("select mxid from global_threepid_associations where "
                    "medium = ? and lower(address) = lower(?) and notBefore < ? and notAfter > ? "
                    "order by ts desc limit 1",
                    (medium, address, time_msec(), time_msec()))

        row = res.fetchone()

        if not row:
            return None

        return row[0]

    def getMxids(self, threepid_tuples):
        # If exists LDAP configuration
        # Perform LDAP lookup
        # If LDAP lookup result empty perform database lookup
        threepid_for_db_lookup = []
        results = []
        if self.sydent.ldap.HasLdapConfiguration():
            threepid_for_db_lookup = []
            for request in threepid_tuples:
                res = self.sydent.ldap.getMxid(request[0],request[1])
                if res:
                    results.append(res)
                else:
                    # Not found. Need to lookup in database
                    threepid_for_db_lookup.append(request)
        else:
            # Search all in database
            threepid_for_db_lookup = threepid_tuples
        # TODO I think we don't perform 3pid assotiation if it exists in LDAP.
        cur = self.sydent.db.cursor()
        cur.execute("CREATE TEMPORARY TABLE tmp_getmxids (medium VARCHAR(16), address VARCHAR(256))");
        cur.execute("CREATE INDEX tmp_getmxids_medium_lower_address ON tmp_getmxids (medium, lower(address))");
        try:
            inserted_cap = 0
            while inserted_cap < len(threepid_for_db_lookup):
                cur.executemany(
                    "INSERT INTO tmp_getmxids (medium, address) VALUES (?, ?)",
                    threepid_for_db_lookup[inserted_cap:inserted_cap + 500]
                )
                inserted_cap += 500

            res = cur.execute(
                # 'notBefore' is the time the association starts being valid, 'notAfter' the the time at which
                # it ceases to be valid, so the ts must be greater than 'notBefore' and less than 'notAfter'.
                "SELECT gte.medium, gte.address, gte.ts, gte.mxid FROM global_threepid_associations gte "
                "JOIN tmp_getmxids ON gte.medium = tmp_getmxids.medium AND lower(gte.address) = lower(tmp_getmxids.address) "
                "WHERE gte.notBefore < ? AND gte.notAfter > ? "
                "ORDER BY gte.medium, gte.address, gte.ts DESC",
                (time_msec(), time_msec())
            )

            current = ()
            for row in res.fetchall():
                # only use the most recent entry for each
                # threepid (they're sorted by ts)
                if (row[0], row[1]) == current:
                    continue
                current = (row[0], row[1])
                results.append((row[0], row[1], row[3]))

        finally:
            res = cur.execute("DROP TABLE tmp_getmxids")

        return results

    def addAssociation(self, assoc, rawSgAssoc, originServer, originId, commit=True):
        """
        :param assoc: (sydent.threepid.GlobalThreepidAssociation) The association to add as a high level object
        :param sgAssoc The original raw bytes of the signed association
        :return:
        """
        cur = self.sydent.db.cursor()
        res = cur.execute("insert or ignore into global_threepid_associations "
                          "(medium, address, mxid, ts, notBefore, notAfter, originServer, originId, sgAssoc) values "
                          "(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                          (assoc.medium, assoc.address, assoc.mxid, assoc.ts, assoc.not_before, assoc.not_after,
                          originServer, originId, rawSgAssoc))
        if commit:
            self.sydent.db.commit()

    def lastIdFromServer(self, server):
        cur = self.sydent.db.cursor()
        res = cur.execute("select max(originId),count(originId) from global_threepid_associations "
                          "where originServer = ?", (server,))
        row = res.fetchone()

        if row[1] == 0:
            return None

        return row[0]
