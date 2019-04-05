package no.kantega.security.api.impl.ldap;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSocketFactory;

import java.io.Closeable;
import java.io.IOException;

public class CloseableLdapConnection extends LDAPConnection implements Closeable {
    public CloseableLdapConnection() {
        super();
    }

    public CloseableLdapConnection(LDAPSocketFactory ldapSocketFactory) {
        super(ldapSocketFactory);
    }

    @Override
    public void close() throws IOException {
        try {
            disconnect();
        } catch (LDAPException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}
