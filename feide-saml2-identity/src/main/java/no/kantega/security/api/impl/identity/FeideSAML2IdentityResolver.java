package no.kantega.security.api.impl.identity;

import no.kantega.security.api.identity.*;
import no.ntnu.it.fw.saml2api.*;
import no.ntnu.it.fw.saml2api.exthiggins.SAMLLogoutResponse;
import no.ntnu.it.fw.saml2api.http.Common;
import org.apache.log4j.Logger;
import org.eclipse.higgins.saml2idp.saml2.SAMLAssertion;
import org.eclipse.higgins.saml2idp.saml2.SAMLConstants;
import org.eclipse.higgins.saml2idp.saml2.SAMLResponse;
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
public class FeideSAML2IdentityResolver implements IdentityResolver {
    private static Logger log = Logger.getLogger(FeideSAML2IdentityResolver.class);
    private String authenticationContext = "Feide";
    private String authenticationContextDescription = "FeideID";
    private String authenticationContextIconUrl = "";

    private String spConfFilePath;

    public AuthenticatedIdentity getIdentity(HttpServletRequest request) throws IdentificationFailedException {
        init(request.getSession());
        DefaultAuthenticatedIdentity identity = null;

        HttpSession session = request.getSession(false);

        String samlResponseArg = request.getParameter(Constants.PARAMETER_SAMLRESPONSE);
        if(samlResponseArg != null ){
            createEduPerson(session, samlResponseArg);

        }
        String relayState = request.getParameter(Constants.PARAMETER_RELAYSTATE);

        if (relayState == null) {
            log.error("Required parameter " + Constants.PARAMETER_RELAYSTATE + " not found.");
            return null;
        }


        EduPerson eduPerson;
        boolean sessionExist = session != null;
        boolean eduPersonExist = (eduPerson = Common.getEduPerson(session)) != null;
        boolean isAuthenticated = sessionExist && eduPersonExist;
        if (isAuthenticated){
            /**********************************************************
             * The user is logged on.
             * ********************************************************/
            identity = new DefaultAuthenticatedIdentity(this);
            identity.setUserId(eduPerson.getUsername());
            identity.setDomain(authenticationContext);

        }
        return identity;
    }

    private void init(HttpSession session) {
        if(session == null){
            throw new IllegalArgumentException("Session was null");
        }
        ServletContext servletContext = session.getServletContext();
        try {
            String fullspConfFilePath = checkContextPath(spConfFilePath, servletContext);
            SPConf spConf =  new SPConf(fullspConfFilePath);

            String idpConfFile = checkContextPath(spConf.getIdpConfFile(), servletContext);

            IDPConf idpConf = new IDPConf(idpConfFile);

            Common.setConfigIDP(servletContext, idpConf);
            Common.setConfigSP(servletContext, spConf);
        } catch (ConfigurationException e) {
            log.error("Error when initializing", e);
        }
    }

    /**
     * If the path starts with /WEB-INF/ it is asumed that the file is in the context and
     * the real context path is returned.
     * @param path Path of the file - can not be null.
     * @return Return File path string
     * @throws ConfigurationException If init param is null or an empty string
     */
    private String checkContextPath(String path, ServletContext servletContext){
        if (path.startsWith("/WEB-INF/")){
            path = servletContext.getRealPath(path);
        }
        return path;
    }

    private void createEduPerson(HttpSession session, String samlResponseArg) {
        try {
            initiateEduPerson(session, samlResponseArg);
        } catch (SAML2Exception e) {
            log.error("Could not create EduPerson");
        }
    }

    private void initiateEduPerson(HttpSession session, String samlResponseArg) throws SAML2Exception {
        SAMLResponse samlResponse = SAML2Util.parseSAMLResponse(samlResponseArg);

        ServletContext servletContext = session.getServletContext();
        IDPConf idpConfig = Common.getConfigIDP(servletContext);
        SPConf spConfig = Common.getConfigSP(servletContext);

        if (spConfig.getWantSignedAssertions()){
            SAML2Util.verifySignature(samlResponse, idpConfig.getPublicKey());
        }

        String statusCodeValue = samlResponse.getStatusCodeValue();

        if (! statusCodeValue.equals(SAMLConstants.STATUSCODE_SUCCESS)) {
            log.error("Samlresponse statuscode not STATUSCODE_SUCCESS");
        }

        SAMLAssertion samlAssertion = samlResponse.getSAMLAssertion();
        String nameId = samlAssertion.getSubject().getNameID();
        String sessionIndex = SAML2Util.parseSessionIndex(samlAssertion);
        Common.setNameID(session, nameId);
        Common.setSessionIndex(session, sessionIndex);

        EduPerson eduPerson = SAML2Util.createEduPerson(samlAssertion, idpConfig.isAttribValuesBase64Encoded(), idpConfig.getFeideSplitChar());

        Common.setEduPerson(session, eduPerson);
    }

    public void initateLogin(LoginContext loginContext) {
        HttpServletResponse response = loginContext.getResponse();
        HttpServletRequest request = loginContext.getRequest();
        HttpSession session = request.getSession();
        init(session);

        avoidCaching(response);
        try {

            String relayState = loginContext.getTargetUri().toString();
            String samlResponseArg = request.getParameter(Constants.PARAMETER_SAMLRESPONSE);

            ServletContext servletContext = request.getSession().getServletContext();
            IDPConf idpConfig = Common.getConfigIDP(servletContext);
            SPConf spConfig = Common.getConfigSP(servletContext);

            String loginUrl;

            boolean sessionExist = session != null;
            boolean eduPersonExist = Common.getEduPerson(session) != null;
            boolean isAuthenticated = sessionExist && eduPersonExist;
            if (isAuthenticated){
                /**********************************************************
                 * The user is logged on. Just let it pass through.
                 * ********************************************************/
                 loginUrl = loginContext.getTargetUri().toString();

            } else if (samlResponseArg != null) {
                /**********************************************************
                 * Handle a authn. response from the IDP
                 * ********************************************************/

                log.debug("LoginServlet: handle response from IDP. Relaystate is: " + relayState);

                SAMLResponse samlResponse = SAML2Util.parseSAMLResponse(samlResponseArg);

                if (spConfig.getWantSignedAssertions()){
                    SAML2Util.verifySignature(samlResponse, idpConfig.getPublicKey());
                }

                log.debug(SAML2Util.dom2String(samlResponse.getDocument()));

                String statusCodeValue = samlResponse.getStatusCodeValue();

                if (! statusCodeValue.equals(SAMLConstants.STATUSCODE_SUCCESS)) {
                    throw new IllegalStateException("User NOT successfully logged in. SAMLResponseStatusCode:" + statusCodeValue);
                }

                createAndSetEduPerson(session, relayState, idpConfig, samlResponse);

                loginUrl = loginContext.getTargetUri().toString();

            }else{
                /***********************************************
                 * Start a login procedure and redirect to IdP
                 **********************************************/
                log.debug("Starting a logon procedure");

                loginUrl = SAML2Util.createSAMLAuthnRequest(idpConfig, spConfig, relayState);
            }

            log.debug("Redirect to: " + loginUrl + ".");
            response.sendRedirect(loginUrl);

        } catch (Exception e) {
            try {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Ikke autentisert - SAMLResponseStatusCode:");
            } catch (IOException e1) {
                log.error("error", e1);
            }
        }
    }

    private void createAndSetEduPerson(HttpSession session, String relayState, IDPConf idpConfig, SAMLResponse samlResponse) throws SAML2Exception {
        SAMLAssertion samlAssertion = samlResponse.getSAMLAssertion();

        // Save nameID & sessionIndex in session, to be used in logout
        String nameId = samlAssertion.getSubject().getNameID();
        String sessionIndex = SAML2Util.parseSessionIndex(samlAssertion);
        Common.setNameID(session, nameId);
        Common.setSessionIndex(session, sessionIndex);

        // Build the internal user-data from the asserion
        EduPerson eduPerson = SAML2Util.createEduPerson(samlAssertion, idpConfig.isAttribValuesBase64Encoded(), idpConfig.getFeideSplitChar());

        // Set the internal user-data in the session
        Common.setEduPerson(session, eduPerson);

        log.debug(eduPerson.dump());
        log.debug("SAML2Util.handleSAMLResponse: redirecting to: " + relayState);
    }

    public void initiateLogout(LogoutContext logoutContext) {
        HttpServletResponse response = logoutContext.getResponse();
        HttpServletRequest request = logoutContext.getRequest();

        avoidCaching(response);


        ServletContext servletContext = request.getSession().getServletContext();
        SPConf spConfig = Common.getConfigSP(servletContext);
        IDPConf idpConfig = Common.getConfigIDP(servletContext);

        try {
            String logoutUrl = getLogoutUrl(logoutContext, spConfig, idpConfig);
            log.debug("Redirect to: " + logoutUrl + ".");

            request.getSession().invalidate();
            response.sendRedirect(logoutUrl);
        } catch (Exception e) {
            log.error("Error logging out", e);
        }
    }

    private String getLogoutUrl(LogoutContext logoutContext, SPConf spConfig, IDPConf idpConfig) throws SAML2Exception, IOException {
        HttpServletRequest request = logoutContext.getRequest();
        String logoutRequestStr = request.getParameter(Constants.PARAMETER_SAMLREQUEST);
        String logoutResponseStr = request.getParameter(Constants.PARAMETER_SAMLRESPONSE);
        String relayState = request.getParameter(Constants.PARAMETER_RELAYSTATE);

        String logoutUrl;
        if (logoutRequestStr != null) {
            /********************************************
             * There has been a LogoutRequest from IDP.
             ********************************************/

            logoutUrl = SAML2Util.createSAMLLogoutResponse(idpConfig, spConfig,
                    logoutRequestStr,
                    relayState);

            log.debug("Send LogoutResponse, Redirect to: " + logoutUrl + ".");
        } else if (logoutResponseStr != null) {
            /********************************************
             * We have got a LogoutResponse from IDP.
             ********************************************/

            // Parse the response fra IDP
            SAMLLogoutResponse samlLogoutResponse = SAML2Util.parseSAMLogoutResponse(logoutResponseStr);

            log.debug("Parsed LogoutResponse:" + SAML2Util.dom2String(samlLogoutResponse.getDocument()));

            logoutUrl = relayState;
        } else {
            /****************************************************************
             * We want to start a SLO by sending a logout request to the IDP
             ****************************************************************/

            // Use a predefined page as RelayState
            String logoutPage = logoutContext.getTargetUri().toASCIIString();

            // Retrieve the namID & sessionIndex from the session.
            HttpSession session = request.getSession();
            String nameID = Common.getNameID(session);
            String sessionIndex = Common.getSessionIndex(session);

            // Create the URL to redirect to
            logoutUrl = SAML2Util.createSAMLLogoutRequest(idpConfig, spConfig, nameID, sessionIndex, logoutPage);

            log.debug("Redirect to: " + logoutUrl + ".");
        }
        return logoutUrl;
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

    public String getAuthenticationContextDescription() {
        return authenticationContextDescription;
    }

    public String getAuthenticationContextIconUrl() {
        return authenticationContextIconUrl;
    }

    @Required
    public void setSpConfFilePath(String spConfFilePath) {
        this.spConfFilePath = spConfFilePath;
    }
}
