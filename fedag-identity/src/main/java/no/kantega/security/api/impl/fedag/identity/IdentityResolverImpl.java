package no.kantega.security.api.impl.fedag.identity;

import no.kantega.security.api.identity.*;
import no.kantega.security.api.impl.fedag.database.DatabaseAccess;
import no.kantega.security.api.impl.fedag.identity.IdentityImpl;
import no.kantega.security.api.impl.fedag.config.Config;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.StringTokenizer;
import java.util.Properties;
import java.net.URLEncoder;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.log4j.Logger;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.beans.factory.InitializingBean;

/**
 * User: stelin
 * Date: 10.nov.2006
 * Time: 09:45:07
 */
public class IdentityResolverImpl implements IdentityResolver, InitializingBean {
    private Logger logger = Logger.getLogger(getClass());
    private DatabaseAccess dbAccess = new DatabaseAccess();

    private JdbcTemplate jdbcTemplate;

    //session parameters
    private static final String SESSION_IDFAILED_EXCEPTION = "SESSION_IDFAILED_EXCEPTION";
    private static final String SESSION_IDENTITY_NAME = "SESSION_IDENTITY";

    //user attributes retrieved during login and some used during logout
    private static final String TARGET_PARAMETER_NAME = "relayState";
    private static final String PROFILE_PARAMETER_NAME = "profile";
    private static final String AUTHN_CONTEXT_PARAMETER_NAME = "saml:authenticationContext";
    public static final String SUBJECT_NAME_ID_PARAMETER_NAME = "saml:subjectNameId";
    public static final String SESSION_INDEX_PARAMETER_NAME = "saml:sessionIndex";
    private static final String IS_SESSION_VALID = "IS_SESSION_VALID";

    //artifact attribute from FedAg used during login
    private static final String ARTIFACT_PARAMETER_NAME = "artifact";

    //attributes from IdentityService
    private static final String NATIONAL_ID = "nationalId";
    private static final String LANGUAGE_PARAMETER_NAME = "language";

    //configurable parameters
    private String fedAgUrl;
    private String identityServiceUrl;
    private String fedagProfile;
    private String sessionTablename;
    private String defaultAutnTarget;
    private String defaultLogoutTarget;
    private String fedAgLogoutUrl;

    //context parameters
    private String authenticationContext;
    private String authenticationContextDescription;
    private String authenticationContextIconUrl;

    private Config config;

    public AuthenticatedIdentity getIdentity(HttpServletRequest request) throws IdentificationFailedException {
        HttpSession session = request.getSession();
        IdentificationFailedException idfailException = (IdentificationFailedException) session.getAttribute(authenticationContext + SESSION_IDFAILED_EXCEPTION);

        //checks for previous errors
        if (idfailException != null) {
            logger.error("getIdentity() Found IdentificationFailedException in HttpSession from initiateLogin()", idfailException);
            session.removeAttribute(SESSION_IDFAILED_EXCEPTION);
            throw idfailException;
        } else {
            AuthenticatedIdentity identity = (AuthenticatedIdentity) session.getAttribute(authenticationContext + SESSION_IDENTITY_NAME);

            //looks for session validity in request attribute
            boolean isSessionValid = Boolean.TRUE.equals(request.getAttribute(authenticationContext + IS_SESSION_VALID));

            if(!isSessionValid) {
                //if not found get session from database
                isSessionValid = validateSessionInDatabase(identity);
                logger.info("Session status in database: " + isSessionValid);
                request.setAttribute(authenticationContext + IS_SESSION_VALID, Boolean.valueOf(isSessionValid));
            }

            if (isSessionValid) {
                logger.info("Returned valid identity: " + identity);
                return identity;
            } else {
                //checks for artifact from Federation Agent
                String artifact = request.getParameter(ARTIFACT_PARAMETER_NAME);

                if (artifact != null) {
                    String identityString = getIdentityFromIdentityService(artifact);
                    AuthenticatedIdentity newIdentity = parseIdentityString(identityString);
                    logger.debug("Identity established from IdentityServer: " + newIdentity);
                    if (newIdentity != null) {
                        storeSessionInDatabase(newIdentity.getRawAttributes());
                    }
                    request.getSession().setAttribute(authenticationContext + SESSION_IDENTITY_NAME, newIdentity);
                    return newIdentity;
                } else {
                    logger.info("Session in database not valid and no artifact found. This means an external global logout is performed. Removes identity from session");
                    session.removeAttribute(authenticationContext + SESSION_IDENTITY_NAME);
                    return null;
                }
            }
        }
    }

    private boolean validateSessionInDatabase(AuthenticatedIdentity identity) {
        if (identity == null) {
            return false;
        }
        String subjectNameId = (String) identity.getRawAttributes().get(SUBJECT_NAME_ID_PARAMETER_NAME);
        String sessionIndex = (String) identity.getRawAttributes().get(SESSION_INDEX_PARAMETER_NAME);
        return subjectNameId != null && sessionIndex != null && dbAccess.checkSession(subjectNameId, sessionIndex, sessionTablename);
    }

    public void initateLogin(LoginContext loginContext) {
        //removes an identity if exists in session
        HttpSession session = loginContext.getRequest().getSession();
        AuthenticatedIdentity identity = (AuthenticatedIdentity) session.getAttribute(authenticationContext + SESSION_IDENTITY_NAME);
        session.removeAttribute(authenticationContext + SESSION_IDENTITY_NAME);
        if (identity!=null){
            logger.info("Identity was found in session during initiateLogin. Removing this identity.");
            Properties p = identity.getRawAttributes();
            dbAccess.deleteSession((String)p.get(SUBJECT_NAME_ID_PARAMETER_NAME), (String)p.get(SESSION_INDEX_PARAMETER_NAME));
        }

        try {
            redirectToFedAg(loginContext);
        } catch (IOException e) {
            String msg = "Error redirecting to Federation Agent";
            IdentificationFailedException idFailedException = new IdentificationFailedException("005", msg + e);
            loginContext.getRequest().getSession().setAttribute(authenticationContext + SESSION_IDFAILED_EXCEPTION, idFailedException);
            logger.error(msg, e);
        }
    }

    private void storeSessionInDatabase(Properties identityAttributes) throws IdentificationFailedException {
        String subjectNameId = (String) identityAttributes.get(SUBJECT_NAME_ID_PARAMETER_NAME);
        String sessionIndex = (String) identityAttributes.get(SESSION_INDEX_PARAMETER_NAME);
        if (subjectNameId == null && sessionIndex == null) {
            throw new IdentificationFailedException("009", SUBJECT_NAME_ID_PARAMETER_NAME + " or " + SESSION_INDEX_PARAMETER_NAME + " not found in state during login.");
        }
        dbAccess.insertSession(subjectNameId, sessionIndex, sessionTablename);
    }

    private String getIdentityFromIdentityService(String sessionId) throws IdentificationFailedException {
        HttpClient client = new HttpClient();
        logger.debug("Posting sid: " + sessionId + " to IdentityService: " + identityServiceUrl);
        PostMethod method = new PostMethod(identityServiceUrl);
        method.addParameter(ARTIFACT_PARAMETER_NAME, sessionId);
        try {
            int statuscode = client.executeMethod(method);
            if (statuscode != HttpStatus.SC_OK) {
                String msg = "Failed while calling Identity Service. HttpStatus response code: " + statuscode;
                logger.error(msg, null);
                throw new IdentificationFailedException("003", msg);
            }
            String idResponse = method.getResponseBodyAsString();
            logger.debug("Identity Service response: " + idResponse);
            if (idResponse == null || "".equals(idResponse)) {
                throw new IdentificationFailedException("003", "Identity from IdentityService was null or blank: -->" + idResponse + "<--");
            }
            return idResponse;
        }
        catch (IOException e) {
            String msg = "Failed while calling Identity Service.";
            logger.error(msg, e);
            throw new IdentificationFailedException("002", msg + e);
        }
        finally {
            method.releaseConnection();
        }
    }

    private AuthenticatedIdentity parseIdentityString(String idResponse) {
        if (idResponse == null) {
            return null;
        }

        StringTokenizer splitId = new StringTokenizer(idResponse, ";");
        IdentityImpl identity = new IdentityImpl(this);
        while (splitId.hasMoreTokens()) {
            String oneParam = splitId.nextToken();
            String paramName;
            String paramValue;
            //allows empty parameters
            int indexOf = oneParam.indexOf('=');
            if (indexOf < 0 || indexOf == oneParam.length()) {
                paramName = oneParam;
                paramValue = "";
            } else {
                paramName = oneParam.substring(0, indexOf).trim();
                paramValue = oneParam.substring(indexOf + 1).trim();
            }

            if (NATIONAL_ID.equals(paramName)) {
                identity.setUserId(paramValue);
            } else if (LANGUAGE_PARAMETER_NAME.equals(paramName)) {
                identity.setLanguage(paramValue);
            } else {
                identity.getRawAttributes().setProperty(paramName, paramValue);
            }
            logger.debug("Adding attribute to identity: " + paramName + "=" + paramValue);
        }

        if (identity.getUserId() == null ||
                identity.getRawAttributes().get(SUBJECT_NAME_ID_PARAMETER_NAME) == null ||
                identity.getRawAttributes().get(SESSION_INDEX_PARAMETER_NAME) == null) {
            logger.error(NATIONAL_ID + ", " + SUBJECT_NAME_ID_PARAMETER_NAME + " and/or " + SESSION_INDEX_PARAMETER_NAME + " not retrieved from IdentityService. Identity set to null");
            identity = null;
        }

        return identity;
    }

    private void redirectToFedAg(LoginContext loginContext) throws IOException {
        String targetUrl;
        if (loginContext.getTargetUri() != null) {
            targetUrl = loginContext.getTargetUri().toASCIIString();
        } else {
            logger.debug("Using default authn-target from config.");
            targetUrl = defaultAutnTarget;
        }

        String redirectUrl;
        if (fedAgUrl.indexOf("?") > 0) {
            redirectUrl = fedAgUrl + "&";
        } else {
            redirectUrl = fedAgUrl + "?";
        }
        redirectUrl += TARGET_PARAMETER_NAME + "=" + URLEncoder.encode(targetUrl, "UTF-8") +
                "&" + AUTHN_CONTEXT_PARAMETER_NAME + "=" + authenticationContext +
                "&" + PROFILE_PARAMETER_NAME + "=" + fedagProfile;

        logger.info("Redirects to Federation Agent for login. Http request: " + targetUrl);
        loginContext.getResponse().sendRedirect(redirectUrl);
    }

    public void initiateLogout(LogoutContext logoutContext) {
        HttpServletRequest request = logoutContext.getRequest();
        HttpServletResponse response = logoutContext.getResponse();
        AuthenticatedIdentity identity = (AuthenticatedIdentity) request.getSession().getAttribute(authenticationContext + SESSION_IDENTITY_NAME);

        if (identity == null) {
            logger.info("Logout initiated, but no identity found in session. Doing nothing.");
            return;
        }

        String subjectNameId = (String) identity.getRawAttributes().get(SUBJECT_NAME_ID_PARAMETER_NAME);
        String sessionIndex = (String) identity.getRawAttributes().get(SESSION_INDEX_PARAMETER_NAME);
        //local logout 1
        request.getSession().removeAttribute(authenticationContext + SESSION_IDENTITY_NAME);
        if (subjectNameId == null || sessionIndex == null) {
            logger.info("Logout initiated. Identity found in session but the attributes " + SUBJECT_NAME_ID_PARAMETER_NAME + " and/or " + SESSION_INDEX_PARAMETER_NAME + " not found. Only removing identity locally.");
            return;
        }
        //local logout 2
        dbAccess.deleteSession(subjectNameId, sessionIndex);

        String target;
        if (logoutContext.getTargetUri() != null) {
            target = logoutContext.getTargetUri().toASCIIString();
        } else {
            logger.info("Using default logout target from config.");
            target = defaultLogoutTarget;
        }

        //global logout
        try {
            //building logout url
            String url = fedAgLogoutUrl;
            url += "?";
            url += SESSION_INDEX_PARAMETER_NAME + "=" + sessionIndex;
            url += "&";
            url += SUBJECT_NAME_ID_PARAMETER_NAME + "=" + subjectNameId;
            url += "&";
            url += TARGET_PARAMETER_NAME + "=" + URLEncoder.encode(target, "UTF-8");
            logger.info("Redirected to Federation Agent for logout: " + url);
            response.sendRedirect(url);
        } catch (IOException e) {
            String msg = "Error during redirect for logout";
            logger.error(msg, e);
            try {
                response.sendError(500, msg);
            }
            catch (IOException e1) {
                logger.error("Error doing sendError" + e);
            }
        }

    }

    public void setJdbcTemplate(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        dbAccess.setJdbcTemplate(jdbcTemplate);
    }

    public String getAuthenticationContext() {
        return authenticationContext;
    }

    public String getAuthenticationContextDescription() {
        return authenticationContextDescription;
    }

    public String getAuthenticationContextIconUrl() {
        return authenticationContextIconUrl;
    }

    public void setAuthenticationContext(String authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    public void setAuthenticationContextDescription(String authenticationContextDescription) {
        this.authenticationContextDescription = authenticationContextDescription;
    }

    public void setAuthenticationContextIconUrl(String authenticationContextIconUrl) {
        this.authenticationContextIconUrl = authenticationContextIconUrl;
    }

    public void setConfig(Config config) {
        this.config = config;
        dbAccess.setConfig(config);
    }

    public void afterPropertiesSet() throws Exception {
        fedAgUrl = config.getFedAgUrl();
        fedAgUrl = config.getFedAgUrl();
        identityServiceUrl = config.getIdentityServiceUrl();
        fedagProfile = config.getFedAgpProfile();
        sessionTablename = config.getSessionTableName();
        defaultAutnTarget = config.getDefaultAuthenticationTarget();
        defaultLogoutTarget = config.getDefaultLogoutTargetUrl();
        fedAgLogoutUrl = config.getFedagLogoutUrl();
    }
}
