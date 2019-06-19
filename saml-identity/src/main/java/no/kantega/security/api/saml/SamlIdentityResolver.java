package no.kantega.security.api.saml;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.SettingsException;
import no.kantega.security.api.identity.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Properties;

public class SamlIdentityResolver implements IdentityResolver {
    private static final Logger log = LoggerFactory.getLogger(SamlIdentityResolver.class);

    private String configFile;
    private String authenticationContext = "saml";

    @Override
    public AuthenticatedIdentity getIdentity(HttpServletRequest request) throws IdentificationFailedException {
        final String authorizedPrincipal = (String) request.getSession().getAttribute(SamlServlet.AUTORIZED_PRINCIPAL_SESSION_ATTRIBUTE);
        log.debug("authorizedPrincipal: {}", authorizedPrincipal);
        return authorizedPrincipal == null ? null : new SamlIdentity(this, authorizedPrincipal);
    }

    @Override
    public void initateLogin(LoginContext loginContext) {
        log.debug("initateLogin {}", loginContext.getTargetUri());
        HttpServletRequest request = loginContext.getRequest();
        HttpServletResponse response = loginContext.getResponse();
        try {
            Auth auth = new Auth(configFile, request, response);
            auth.login(loginContext.getTargetUri().toString());
        } catch (SettingsException | IOException | Error e) {
            throw new RuntimeException("Error initiating login", e);
        }
    }

    @Override
    public void initiateLogout(LogoutContext logoutContext) {
        log.debug("initateLogin {}", logoutContext.getTargetUri());
        logoutContext.getRequest().getSession().removeAttribute(SamlServlet.AUTORIZED_PRINCIPAL_SESSION_ATTRIBUTE);
        String targetUrl = "/";
        if (logoutContext.getTargetUri() != null) {
            targetUrl = logoutContext.getTargetUri().toASCIIString();
            targetUrl = targetUrl.replaceAll("<", "");
            targetUrl = targetUrl.replaceAll(">", "");
        }

        try {
            logoutContext.getResponse().sendRedirect(targetUrl);
        } catch (IOException e) {

        }
    }

    public String getAuthenticationContext() {
        return authenticationContext;
    }

    public String getAuthenticationContextDescription() {
        return "";
    }

    public String getAuthenticationContextIconUrl() {
        return "";
    }

    public void setAuthenticationContext(String authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    public String getConfigFile() {
        return configFile;
    }

    private static class SamlIdentity implements AuthenticatedIdentity {
        private final IdentityResolver identityResolver;
        private final String authorizedPrincipal;

        private SamlIdentity(IdentityResolver identityResolver, String authorizedPrincipal) {
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
}
