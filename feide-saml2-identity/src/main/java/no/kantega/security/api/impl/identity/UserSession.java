package no.kantega.security.api.impl.identity;

import no.kantega.security.api.identity.Identity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

public class UserSession {
    private static Logger log = LoggerFactory.getLogger(UserSession.class);
    private Identity identity;
    private String samlNameId;
    private String samlSessionIndex;
    private Date sessionExpireDate;
    private int sessionMaxAge = 60*4;

    public UserSession() {
        this.sessionExpireDate = new Date();
        this.sessionExpireDate.setTime(sessionExpireDate.getTime() + (sessionMaxAge * 60 * 1000));
    }

    public Identity getIdentity() {
        return identity;
    }

    public void setIdentity(Identity identity) {
        this.identity = identity;
    }

    public String getSamlNameId() {
        return samlNameId;
    }

    public void setSamlNameId(String samlNameId) {
        this.samlNameId = samlNameId;
    }

    public String getSamlSessionIndex() {
        return samlSessionIndex;
    }

    public void setSamlSessionIndex(String samlSessionIndex) {
        this.samlSessionIndex = samlSessionIndex;
    }

    public boolean isValid() {
        Date now = new Date();
        if (sessionExpireDate.getTime() > now.getTime()) {
            return true;
        } else {
            return false;
        }
    }
}
