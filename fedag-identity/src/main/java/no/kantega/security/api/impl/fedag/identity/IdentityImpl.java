package no.kantega.security.api.impl.fedag.identity;

import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.identity.IdentityResolver;
import no.kantega.security.api.identity.AuthenticatedIdentity;

import java.util.Properties;

/**
 * User: stelin
 * Date: 10.nov.2006
 * Time: 09:42:04
 */
public class IdentityImpl implements AuthenticatedIdentity {
    private String userId;
    private String language;
    private Properties rawAttributes = new Properties();
    private IdentityResolver resolver;

    public IdentityImpl(IdentityResolver resolver) {
        this.resolver = resolver;
    }

    public String getUserId() {
        return userId;
    }

    public String getDomain() {
        return resolver.getAuthenticationContext();
    }

    public String getLanguage() {
        return language;
    }

    public Properties getRawAttributes() {
        return rawAttributes;
    }

    public IdentityResolver getResolver() {
        return resolver;
    }


    public void setUserId(String userId) {
        this.userId = userId;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public String toString(){
        return userId + "@" + language + " # " + rawAttributes;
    }
}
