package no.kantega.security.api.impl.ldap.password;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPReferralException;
import com.novell.ldap.LDAPSearchResults;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.impl.ldap.LdapConfigurable;
import no.kantega.security.api.password.PasswordManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Password manager that verifies password by binding to ldap server
 * using <code>usernameAttribute</code>, and optionally <code>objectClassUsers</code>.
 */
public class LdapPasswordManager extends LdapConfigurable implements PasswordManager {
    private String domain;
    private Logger log = LoggerFactory.getLogger(getClass());

    public boolean verifyPassword(Identity identity, String password) throws SystemException {
        if (password == null || password.length() == 0) {
            return false;
        }

        LDAPConnection c = new LDAPConnection();

        final String userId = escapeChars( identity.getUserId() );

        try {

            // Kople opp som admin bruker for � finne DN for bruker
            c.connect(host, port);
            String filter = "";
            if (objectClassUsers.length() > 0) {
                filter = "(&(objectclass=" + objectClassUsers + ")(" + usernameAttribute + "=" + userId + "))";
            } else {
                filter = "(" + usernameAttribute + "=" + userId + ")";
            }

            c.bind(LDAPConnection.LDAP_V3, adminUser, adminPassword.getBytes());
            LDAPSearchResults results = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, filter, new String[0], false);
            if (results.hasMore()) {
                // Logg inn som bruker
                try {
                    String userDN = results.next().getDN();

                    c.bind(LDAPConnection.LDAP_V3, userDN, password.getBytes("utf-8"));

                    // Bind OK - login OK
                    log.debug("Password verified for userid: {}", identity.getUserId());
                    return true;
                } catch (LDAPReferralException l) {
                    // Do nothing
                } catch (LDAPException e) {
                    if (e.getResultCode() == LDAPException.CONSTRAINT_VIOLATION) {
                        log.debug("Password verification failed for userid: {} (CONSTRAINT_VIOLATION)", identity.getUserId() );
                        return false;
                    } else if (e.getResultCode() == LDAPException.INVALID_CREDENTIALS) {
                        log.debug("Password verification failed for userid: {} (INVALID_CREDENTIALS)", identity.getUserId() );
                        return false;
                    } else {
                        throw new SystemException("Feil ved verifisering av passord", e);
                    }
                } catch (Exception e) {
                    throw new SystemException("Feil ved verifisering av passord", e);
                }
            }
        } catch (LDAPException e) {
            throw new SystemException("Feil ved lesing fra LDAP", e);
        } finally {
            try {
                c.disconnect();
            } catch (LDAPException e) {
                //
            }
        }

        return false;
    }


    public void setPassword(Identity identity, String string, String string1) throws SystemException {

    }


    public boolean supportsPasswordChange() {
        return false;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

}
