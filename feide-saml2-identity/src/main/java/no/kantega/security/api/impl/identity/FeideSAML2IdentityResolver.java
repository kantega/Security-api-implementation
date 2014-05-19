package no.kantega.security.api.impl.identity;

import no.kantega.security.api.identity.*;
import no.ntnu.it.fw.saml2api.IDPConf;
import no.ntnu.it.fw.saml2api.SAML2Util;
import no.ntnu.it.fw.saml2api.SPConf;
import no.ntnu.it.fw.saml2api.http.Common;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Required;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * @author marlil marlil@kantega.no
 * Based on code in no.ntnu.it.fw.saml2api.http.LoginContext, no.ntnu.it.fw.saml2api.http.LoginContext, no.ntnu.it.fw.saml2api.http.AuthFilter
 */
public class FeideSAML2IdentityResolver extends AbstractFeideConfigurable implements IdentityResolver  {
    private static Logger log = LoggerFactory.getLogger(FeideSAML2IdentityResolver.class);
    private String authenticationContext = "Feide";
    private String authenticationContextDescription = "FeideID";
    private String authenticationContextIconUrl = "";

    public static String SESSION_IDENTITY_NAME = "KANTEGA_HTTPSESSION_IDENTITY";
    public static String SESSION_IDENTITY_DOMAIN = "KANTEGA_HTTPSESSION_IDENTITY_DOMAIN";

    public static String URL_JUMP_TOKEN = "jumpToken";

    private UrlJumpTokenManager tokenManager;
    private UserSessionManager sessionManager;

    public FeideSAML2IdentityResolver() {
        tokenManager = new UrlJumpTokenManager();
        sessionManager = new UserSessionManager();
    }

    public AuthenticatedIdentity getIdentity(HttpServletRequest request) throws IdentificationFailedException {
        HttpSession session = request.getSession();

        String jumpToken = request.getParameter(URL_JUMP_TOKEN);
        if (jumpToken != null) {
            log.debug("Found jumpToken: {}", jumpToken);
            Identity identity = tokenManager.resolveJumpToken(jumpToken);
            if (identity != null) {
                session.setAttribute(authenticationContext + SESSION_IDENTITY_NAME, identity.getUserId());
                session.setAttribute(authenticationContext + SESSION_IDENTITY_DOMAIN, identity.getDomain());
            }
        }

        DefaultAuthenticatedIdentity authenticatedIdentity = getIdentityFromSession(session);

        if (authenticatedIdentity != null) {
            if (!sessionManager.userHasValidSession(authenticatedIdentity)) {
                log.debug("Session has expired for:{}", authenticatedIdentity.getUserId());
                sessionManager.removeUserSession(authenticatedIdentity);
                return null;
            }
        }

        return authenticatedIdentity;
    }

    private DefaultAuthenticatedIdentity getIdentityFromSession(HttpSession session) {
        DefaultAuthenticatedIdentity authenticatedIdentity = null;
        String identity = (String)session.getAttribute(authenticationContext + SESSION_IDENTITY_NAME);
        if (identity != null && identity.length() > 0) {
            int inx = identity.indexOf("\\");
            if (inx != -1) {
                identity = identity.substring(inx + 1, identity.length());
                identity = identity.toLowerCase();
            }

            authenticatedIdentity = new DefaultAuthenticatedIdentity(this);

            String domain = (String)session.getAttribute(authenticationContext + SESSION_IDENTITY_DOMAIN);
            if (domain != null) {
                authenticatedIdentity.setDomain(domain);
            } else {
                authenticatedIdentity.setDomain(authenticationContext);
            }

            authenticatedIdentity.setUserId(identity);
        }
        return authenticatedIdentity;
    }


    public void initateLogin(LoginContext loginContext) {
        HttpServletResponse response = loginContext.getResponse();
        HttpServletRequest request = loginContext.getRequest();
        HttpSession session = request.getSession();

        init(session);

        avoidCaching(response);
        try {
            String relayState = null;
            if (loginContext.getTargetUri() != null) {
                relayState = loginContext.getTargetUri().toString();
            }

            ServletContext servletContext = request.getSession().getServletContext();
            IDPConf idpConfig = Common.getConfigIDP(servletContext);
            SPConf spConfig = Common.getConfigSP(servletContext);

            String loginUrl;

            /***********************************************
             * Start a login procedure and redirect to IdP
             **********************************************/
            log.debug("Starting a logon procedure");

            loginUrl = SAML2Util.createSAMLAuthnRequest(idpConfig, spConfig, relayState);

            log.debug("Redirect to: {}.", loginUrl);
            response.sendRedirect(loginUrl);

        } catch (Exception e) {
            try {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Ikke autentisert - SAMLResponseStatusCode:");
            } catch (IOException e1) {
                log.error("error", e1);
            }
        }
    }

    public void initiateLogout(LogoutContext logoutContext) {
        HttpSession session = logoutContext.getRequest().getSession();

        if (session != null) {
            try {
                Identity identity = getIdentity(logoutContext.getRequest());
                if (identity != null) {
                    sessionManager.removeUserSession(identity);
                }
            } catch (IdentificationFailedException e) {

            }
            session.removeAttribute(authenticationContext + SESSION_IDENTITY_NAME);
        }
        String targetUrl = "/";
        if (logoutContext.getTargetUri() != null) {
            targetUrl = logoutContext.getTargetUri().toASCIIString();
            targetUrl = targetUrl.replaceAll("<", "");
            targetUrl = targetUrl.replaceAll(">", "");
        }

        try {
            logoutContext.getResponse().sendRedirect(targetUrl);
        } catch (IOException e) {
            //
        }
    }

    private void avoidCaching(HttpServletResponse response) {
        // To avoid any form of caching
        response.setHeader("Pragma", "no-cache"); //HTTP/1.0 Proxy Servers
        response.setHeader("Cache-Control", "no-cache, no-store"); //HTTP/1.1 Proxy Servers
        response.setDateHeader("Expires", 0); // for Browsers
    }

    public String getAuthenticationContext() {
        return authenticationContext;
    }

    @Required
    public void setAuthenticationContext(String authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    public String getAuthenticationContextDescription() {
        return authenticationContextDescription;
    }

    public void setAuthenticationContextDescription(String authenticationContextDescription) {
        this.authenticationContextDescription = authenticationContextDescription;
    }

    public String getAuthenticationContextIconUrl() {
        return authenticationContextIconUrl;
    }

    public void setAuthenticationContextIconUrl(String authenticationContextIconUrl) {
        this.authenticationContextIconUrl = authenticationContextIconUrl;
    }

}
