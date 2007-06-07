package no.kantega.security.api.impl.common.password;

import no.kantega.security.api.password.PasswordManager;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.impl.common.CompoundManagerConfigurable;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jun 7, 2007
 * Time: 10:25:57 AM
 */
public class CompoundPasswordManager extends CompoundManagerConfigurable implements PasswordManager {
    public boolean verifyPassword(Identity identity, String password) throws SystemException {
        for (int i = 0; i < managers.size(); i++) {
            PasswordManager pm = (PasswordManager)managers.get(i);
            if (identity.getDomain().equalsIgnoreCase(pm.getDomain())) {
                if (pm.verifyPassword(identity, password)) {
                    return true;
                }
            }
        }

        return false;
    }

    public void setPassword(Identity identity, String string, String string1) throws SystemException {

    }

    public boolean supportsPasswordChange() {
        return false;
    }

}
