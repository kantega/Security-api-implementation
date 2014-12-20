# Security API Implementation

## Compound module
Module to support having multiple security realms simultaneously. For example when it is necessary to 
support authentication with both LDAP and DB-users.


## Database backed authentication and roles
Stores users, roles, and passwords in the database. Uses PBKDF2 With Hmac SHA1 for password hashes.

## LDAP backed authentication and roles
Get users, roles, and check password in Ldap. 
 
## Twofactor authentication DB backed
Generates a login token for the user and store it in the database for later verification.

## Twofactor authentication token sender
Handles sending login tokens to user by email. 