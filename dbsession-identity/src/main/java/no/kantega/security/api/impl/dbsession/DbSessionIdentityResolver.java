package no.kantega.security.api.impl.dbsession;

import no.kantega.security.api.identity.*;
import no.kantega.security.api.impl.dbsession.dao.Session;
import no.kantega.security.api.impl.dbsession.dao.SessionStore;
import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.Properties;


public class DbSessionIdentityResolver implements IdentityResolver {
    private static final String IDENTITY_ATTR_KEY = DbSessionIdentityResolver.class.getName() +"_IDENTITY_ATTR_KEY";
    private String identityKeyParam = "identityKey";
    private SessionStore store;
    private String domain = "dbsession";
    private Logger log = Logger.getLogger(getClass());
    private String redirectAfterLogoutUrl;
    private String authenticationContext = "dbsession";
    private String authenticationService;
    private static final String TARGET_URI_PARAM = "targetUri";

    public AuthenticatedIdentity getIdentity(HttpServletRequest request) throws IdentificationFailedException {
        AuthenticatedIdentity identity = (AuthenticatedIdentity) request.getSession().getAttribute(IDENTITY_ATTR_KEY);
        if(identity != null) {
            if(log.isDebugEnabled()) {
                log.debug("getIdentity returning already logged in user " + identity.getUserId() +" from domain " + identity.getDomain());
            }
            return identity;
        } else {
            String keyValue = request.getParameter(identityKeyParam);
            if(keyValue != null) {
                if(log.isDebugEnabled()) {
                    log.debug("Detected identity key request param " + identityKeyParam +"=" + keyValue +", trying to get session from session store.");
                }
                Session session = store.getSession(keyValue);
                if(session != null) {
                    if(log.isDebugEnabled()) {
                        log.debug("Got session for user " + session.getUsername() +" from store, will now remove it from store.");
                    }
                    store.removeSession(keyValue);
                    if(log.isDebugEnabled()) {
                        log.debug("Creating " + DbSessionAuthenticatedIdentity.class.getName() +" for session and adding it as a http session attribute with key " + IDENTITY_ATTR_KEY);
                    }
                    AuthenticatedIdentity id = new DbSessionAuthenticatedIdentity(session);
                    request.getSession().setAttribute(IDENTITY_ATTR_KEY, id);
                    return id;
                } else {
                    if(log.isDebugEnabled()) {
                        log.debug("No session found in store for key " + keyValue);
                    }
                    return null;
                }
            } else {
                if(log.isDebugEnabled()) {
                    log.debug("User is not logged on and we did not detect a login attempt with parameter " + identityKeyParam);
                }
                return null;
            }

        }
    }

    public void initateLogin(LoginContext loginContext) {
        String targetUri = loginContext.getTargetUri().toString();
        if(targetUri == null) {
            HttpServletRequest request = loginContext.getRequest();
            targetUri = request.getRequestURL().toString();
        }
        String redirectUrl = null;
        try {
            redirectUrl = authenticationService +"?" + TARGET_URI_PARAM +"=" + URLEncoder.encode(targetUri, "utf-8");
            loginContext.getResponse().sendRedirect(redirectUrl);
        } catch (IOException e) {
            throw new RuntimeException("Exception redirecting to uri " + redirectUrl, e);
        }
    }

    public void initiateLogout(LogoutContext logoutContext) {
        if(log.isDebugEnabled()) {
            log.debug("Logging out locally");
        }
        logoutContext.getRequest().getSession().removeAttribute(IDENTITY_ATTR_KEY);
        try {
            if(log.isDebugEnabled()) {
                log.debug("Redirecting user to " + redirectAfterLogoutUrl);
            }
            logoutContext.getResponse().sendRedirect(redirectAfterLogoutUrl);
        } catch (IOException e) {
            throw new RuntimeException("Could not redirect to url " + redirectAfterLogoutUrl, e);
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

    public void setDao(SessionStore store) {
        this.store = store;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public void setRedirectAfterLogoutUrl(String redirectAfterLogoutUrl) {
        this.redirectAfterLogoutUrl = redirectAfterLogoutUrl;
    }

    public void setAuthenticationService(String authenticationService) {
        this.authenticationService = authenticationService;
    }

    class DbSessionAuthenticatedIdentity implements AuthenticatedIdentity {
        private Session session;
        private Properties properties = new Properties();

        public DbSessionAuthenticatedIdentity(Session session) {
            this.session = session;
        }

        public IdentityResolver getResolver() {
            return DbSessionIdentityResolver.this;
        }

        public String getLanguage() {
            return "";
        }

        public Properties getRawAttributes() {
            return properties;
        }

        public String getUserId() {
            return session.getUsername();
        }

        public String getDomain() {
            return domain;
        }
    }
}
