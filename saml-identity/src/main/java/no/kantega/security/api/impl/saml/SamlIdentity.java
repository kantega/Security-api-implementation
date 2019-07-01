package no.kantega.security.api.impl.saml;

import no.kantega.security.api.identity.AuthenticatedIdentity;
import no.kantega.security.api.identity.IdentityResolver;

import java.util.Properties;

class SamlIdentity implements AuthenticatedIdentity {
    private final IdentityResolver identityResolver;
    private final String authorizedPrincipal;

    SamlIdentity(IdentityResolver identityResolver, String authorizedPrincipal) {
        this.identityResolver = identityResolver;
        this.authorizedPrincipal = authorizedPrincipal;
    }

    public String getLanguage() {
        throw new IllegalStateException("Language not implemented");
    }

    public Properties getRawAttributes() {
        throw new IllegalStateException("Raw properties not implemented");
    }

    public IdentityResolver getResolver() {
        return identityResolver;
    }

    public String getUserId() {
        return authorizedPrincipal;
    }

    public String getDomain() {
        return identityResolver.getAuthenticationContext();
    }
}
