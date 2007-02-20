package no.kantega.security.api.impl.ldap.password;

import no.kantega.security.api.password.PasswordManager;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.impl.ldap.LdapConfigurable;
import no.kantega.security.api.common.SystemException;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPSearchResults;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPReferralException;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jan 12, 2007
 * Time: 1:16:33 PM
 */
public class LdapPasswordManager extends LdapConfigurable implements PasswordManager {
    private String domain;

    public boolean verifyPassword(Identity identity, String password) throws SystemException {
        if (password == null || password.length() == 0) {
            return false;
        }

        LDAPConnection c = new LDAPConnection();

        try {

            // Kople opp som admin bruker for å finne DN for bruker
            c.connect(host, port);
            String filter = "";
            if (objectClassUsers.length() > 0) {
                filter = "(&(objectclass=" + objectClassUsers + ")(" + usernameAttribute + "=" + identity.getUserId() + "))";
            } else {
                filter = "(" + usernameAttribute + "=" + identity.getUserId() + ")";
            }

            c.bind(LDAPConnection.LDAP_V3, adminUser, adminPassword.getBytes());
            LDAPSearchResults results = c.search(searchBaseUsers, LDAPConnection.SCOPE_SUB, filter, new String[0], false);
            if (results.hasMore()) {
                // Logg inn som bruker
                try {
                    String userDN = results.next().getDN();

                    c.bind(LDAPConnection.LDAP_V3, userDN, password.getBytes());

                    // Bind OK - login OK
                    return true;
                } catch (LDAPReferralException l) {
                    // Do nothing
                } catch (LDAPException e) {
                    if (e.getResultCode() == LDAPException.CONSTRAINT_VIOLATION) {
                        return false;
                    } else if (e.getResultCode() == LDAPException.INVALID_CREDENTIALS) {
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


    public static void main(String[] args) {
        try {
            LdapPasswordManager manager = new LdapPasswordManager();
            manager.setAdminUser("ad@mogul.no");
            manager.setAdminPassword("Tzg5hh4Vf");
            manager.setDomain("mogul");
            manager.setHost("tom.mogul.no");
            manager.setSearchBaseUsers("ou=Norway,dc=mogul,dc=no");
            manager.setSearchBaseRoles("ou=Norway,dc=mogul,dc=no");

            DefaultIdentity andska = new DefaultIdentity();
            andska.setUserId("andska");
            if (manager.verifyPassword(andska, "********")) {
                System.out.println("Passord er korrekt");
            } else {
                System.out.println("Passord er feil");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
