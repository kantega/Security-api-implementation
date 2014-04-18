package no.kantega.security.api.impl.common.identity;

import no.kantega.security.api.identity.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * IdentityResolver which delegates getIdentity to a list of IdentityResolvers.
 * Other methods are delegated to the <code>mainResolver</code>.
 *
 * Useful when an application has multiple ways of logging in. A common example
 * would be a site set up with Kerberos SSO with a fallback to username / password login.
 */

public class CompoundIdentityResolver implements IdentityResolver {
    private List<IdentityResolver> resolvers;

    private IdentityResolver mainResolver;

    public AuthenticatedIdentity getIdentity(HttpServletRequest httpServletRequest) throws IdentificationFailedException {
        for (IdentityResolver resolver : resolvers) {
            AuthenticatedIdentity id = resolver.getIdentity(httpServletRequest);
            if (id != null) {
                return id;
            }
        }
        return null;
    }

    public void initateLogin(LoginContext loginContext) {
        mainResolver.initateLogin(loginContext);
    }

    public void initiateLogout(LogoutContext logoutContext) {
        mainResolver.initiateLogout(logoutContext);
    }

    public String getAuthenticationContext() {
        return mainResolver.getAuthenticationContext();
    }

    public String getAuthenticationContextDescription() {
        return mainResolver.getAuthenticationContext();
    }

    public String getAuthenticationContextIconUrl() {
        return mainResolver.getAuthenticationContextIconUrl();
    }

    public void setResolvers(List<IdentityResolver> resolvers) {
        this.resolvers = resolvers;
    }

    public void setMainResolver(IdentityResolver mainResolver) {
        this.mainResolver = mainResolver;
    }
}
