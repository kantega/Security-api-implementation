package no.kantega.security.api.impl.identity;

import no.kantega.security.api.identity.Identity;

import java.util.HashMap;
import java.util.Map;

public class UserSessionManager {
    private static Map<String, UserSession> sessions = new HashMap<String, UserSession>();

    public boolean userHasValidSession(Identity identity) {
        String key = getKey(identity);

        UserSession userSession = sessions.get(key);
        if (userSession != null) {
            if (userSession.isValid()) {
                return true;
            } else {
                sessions.remove(key);
                return false;
            }
        } else {
            return false;
        }
    }

    public UserSession getUserSession(Identity identity) {
        String key = getKey(identity);
        return sessions.get(key);
    }


    public void saveUserSession(UserSession userSession) {
        sessions.put(getKey(userSession.getIdentity()), userSession);
    }

    public void removeUserSession(Identity identity) {
        sessions.remove(getKey(identity));
    }

    private String getKey(Identity identity) {
        return identity.getDomain() + ":" + identity.getUserId();
    }
}
