package no.kantega.security.api.impl.identity;

import no.kantega.security.api.identity.Identity;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class UrlJumpTokenManager {
    private static Map<String, Identity> tokens = new HashMap<String, Identity>();

    public String createJumpToken(Identity identity) {
        String token = UUID.randomUUID().toString();
        tokens.put(token, identity);

        return token;
    }

    public Identity resolveJumpToken(String token) {
        return tokens.remove(token);
    }
}
