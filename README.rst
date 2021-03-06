Sydent purpose
==============

In you there is no need to install this component on your server. As an identity server, it is recommended to use matrix.org

You may need to install Sydent, for example, if you deploy an isolated system and users will not be able to access the matrix.org

This is fork main task of which is the implementation of the functional:

- 3pid association based on LDAP data
- proxying to matrix queries that can not be resolved locally

Installation
============

1. Сheck that your system has ``sqlite3 >= 3.16`` (Otherwise there will be syntax errors when working with the database)

2. Run ``pip install https://github.com/matrix-org/sydent/tarball/master``

3. Create user ``useradd -r matrix-sydent`` if not exists

4. ``cp sydent.example.conf /etc/matrix-synapse/sydent.conf`` and edit

5. Copy ``res\verify_response_page_template`` to verify_response_template path 

6. Copy ``res\verification_template.eml`` to email.template path

7. Check that pidfile.path writable by created ``matrix-sydent`` user (e.g. it not created with other owner when you test sydent)

8. Check that log.path exists and writable by created ``matrix-sydent`` user

9. Check that db.file writable by created ``matrix-sydent`` user

10. Check ownership ``chown -R matrix-synapse <path to templates>``

11. Check ownership ``chown -R matrix-synapse /etc/matrix-sydent/``

12. Config systemd ``cp /systemd/matrix-sydent.service /lib/systemd/system/`` and edit it: 

- check that WorkingDirectory exists and writable; 
- check that EnvironmentFile exists; 
- check that service will be run on behalf of the created user

14. After edit do not foget ``systemctl daemon-reload``

15. Start service with ``systemctl start matrix-sydent``


Run for test
============

Dependencies can be installed using setup.py in the same way as synapse: see synapse/README.rst.

Having installed dependencies, you can run sydent using::

    $ python -m sydent.sydent

This will create a configuration file in sydent.conf with some defaults. You'll most likely want to change the server name and specify a mail relay.

3pid lookup order
=================

Threepid search is performed in the following sequence.

If for one of the stages there is not enough configuration - it is skipped.

Threepid found at an earlier stage takes precedence (the first matching is used).

1. LDAP lookup
--------------

For ldap configuration details see `<LDAP.rst>`_ .

2. Request proxying
-------------------

If in config section `[proxy]` present parameter `identity` with URI of other identity server, then `bulk_lookup` request will be sent to this server
with threepids that can not be found in configured LDAP.

3. Database lookup
------------------

Perform local database lookup as original sydent server.

SMS configuration
=================
Defaults for SMS originators will not be added to the generated config file, these should be added in the form::

    originators.<country code> = <long|short|alpha>:<originator>

Where country code is the numeric country code, or 'default' to specify the originator used for countries not listed. For example, to use a selection of long codes for the US/Canda, a short code for the UK and an alphanumertic originator for everywhere else::

    originators.1 = long:12125552368,long:12125552369
    originators.44 = short:12345
    originators.default = alpha:Matrix

Requests
========

The requests that synapse servers and clients submit to the identity server are, briefly, as follows:

Request the validation of your email address:

curl -XPOST 'http://localhost:8090/_matrix/identity/api/v1/validate/email/requestToken' -H "Content-Type: application/json" -d '{"email": "matthew@arasphere.net", "client_secret": "abcd", "send_attempt": 1}'
{"success": true, "sid": "1"}

# receive 943258 by mail

Use this code to validate your email address:

curl -XPOST 'http://localhost:8090/_matrix/identity/api/v1/validate/email/submitToken' -H "Content-Type: application/json" -d '{"token": "943258", "sid": "1", "client_secret": "abcd"}'
{"success": true}

Use the validated email address to bind it to a matrix ID:

curl -XPOST 'http://localhost:8090/_matrix/identity/api/v1/3pid/bind' -H "Content-Type: application/json" -d '{"sid": "1", "client_secret": "abcd", "mxid": "%40matthew%3amatrix.org"}'

# lookup:

curl 'http://localhost:8090/_matrix/identity/api/v1/lookup?medium=email&address=henry%40matrix.org'

# fetch pubkey key for a server

curl http://localhost:8090/_matrix/identity/api/v1/pubkey/ed25519