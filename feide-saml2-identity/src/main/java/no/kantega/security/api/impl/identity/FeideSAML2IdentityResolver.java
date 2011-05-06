package no.kantega.security.api.impl.identity;

import no.kantega.security.api.identity.*;
import no.ntnu.it.fw.saml2api.*;
import no.ntnu.it.fw.saml2api.exthiggins.SAMLLogoutResponse;
import no.ntnu.it.fw.saml2api.http.Common;
import org.apache.log4j.Logger;
import org.eclipse.higgins.saml2idp.saml2.SAMLAssertion;
import org.eclipse.higgins.saml2idp.saml2.SAMLConstants;
import org.eclipse.higgins.saml2idp.saml2.SAMLResponse;

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

    public AuthenticatedIdentity getIdentity(HttpServletRequest request) throws IdentificationFailedException {
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
        if (sessionExist && eduPersonExist){
            /**********************************************************
             * The user is logged on.
             * ********************************************************/
            identity = new DefaultAuthenticatedIdentity(this);
            identity.setUserId(eduPerson.getUsername());
            identity.setDomain(authenticationContext);

        }
        return identity;
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
        String relayState = loginContext.getRequest().getParameter(Constants.PARAMETER_RELAYSTATE);

        ServletContext servletContext = loginContext.getRequest().getSession().getServletContext();
        IDPConf idpConfig = Common.getConfigIDP(servletContext);
        SPConf spConfig = Common.getConfigSP(servletContext);

        try {
            String url = SAML2Util.createSAMLAuthnRequest(idpConfig, spConfig, relayState);
            loginContext.getResponse().sendRedirect(url);

        } catch (Exception e) {
            log.error("Error sending redirect to login", e);
        }
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
        } catch (SAML2Exception e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String getLogoutUrl(LogoutContext logoutContext, SPConf spConfig, IDPConf idpConfig) throws SAML2Exception, IOException {
        HttpServletRequest request = logoutContext.getRequest();
        String logoutRequestStr = request.getParameter(Constants.PARAMETER_SAMLREQUEST);
        String logoutResponseStr = request.getParameter(Constants.PARAMETER_SAMLRESPONSE);
        String relayState = request.getParameter(Constants.PARAMETER_RELAYSTATE);

        String logoutUrl = null;
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
}
