package no.kantega.security.api.impl.saml;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.settings.Saml2Settings;
import no.kantega.security.api.identity.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static no.kantega.security.api.impl.saml.SamlServlet.config;

public class SamlIdentityResolver implements IdentityResolver {
    private static final Logger log = LoggerFactory.getLogger(SamlIdentityResolver.class);

    private Saml2Settings samlConfig;

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
            Auth auth = new Auth(samlConfig, request, response);
            auth.login(loginContext.getTargetUri().toString());
        } catch (Exception e) {
            throw new RuntimeException("Error initiating login", e);
        }
    }

    @Override
    public void initiateLogout(LogoutContext logoutContext) {
        log.debug("initiateLogout {}", logoutContext.getTargetUri());
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
            throw new RuntimeException("Error initiating logout", e);
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

    public void setConfigFile(String configFile) {
        this.samlConfig = config(configFile);
    }

}
