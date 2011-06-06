package no.kantega.security.api.impl.identity;

import no.kantega.security.api.identity.DefaultAuthenticatedIdentity;
import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.identity.Identity;
import no.ntnu.it.fw.saml2api.*;
import no.ntnu.it.fw.saml2api.exthiggins.SAMLLogoutResponse;
import no.ntnu.it.fw.saml2api.http.Common;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class FeideSAML2LogoutController extends AbstractFeideConfigurable implements Controller {
    private static Logger log = Logger.getLogger(FeideSAML2LogoutController.class);
    private String authenticationContext;
    private UserSessionManager userSessionManager;

    private String defaultUnAuthenticatedUrl;

    public FeideSAML2LogoutController() {
        userSessionManager = new UserSessionManager();
    }


    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();

        init(session);
        avoidCaching(response);

        String redirect;
        if (isLogoutRequestFromFeide(request)) {
            redirect = handleLogoutRequestFromFeide(request);
        } else if (isLogoutResponseFromFeide(request)) {
            redirect = handleLogoutResponseFromFeide(request);
        } else {
            redirect = startLogout(request);
        }

        response.sendRedirect(redirect);
        return null;
    }

    private boolean isLogoutRequestFromFeide(HttpServletRequest request) {
        return request.getParameter(Constants.PARAMETER_SAMLREQUEST) != null;
    }

    private boolean isLogoutResponseFromFeide(HttpServletRequest request) {
        return request.getParameter(Constants.PARAMETER_SAMLRESPONSE) != null;
    }

    private String handleLogoutRequestFromFeide(HttpServletRequest request) throws SAML2Exception {
        /********************************************
         * There has been a LogoutRequest from IDP.
         ********************************************/
        ServletContext servletContext = request.getSession().getServletContext();
        IDPConf idpConfig = Common.getConfigIDP(servletContext);
        SPConf spConfig = Common.getConfigSP(servletContext);

        String logoutRequestStr = request.getParameter(Constants.PARAMETER_SAMLREQUEST);
        String relayState = request.getParameter(Constants.PARAMETER_RELAYSTATE);

        String logoutUrl = SAML2Util.createSAMLLogoutResponse(idpConfig, spConfig, logoutRequestStr, relayState);
        log.info("Logout request from IDP, redirect to: " + logoutUrl);
        return logoutUrl;
    }


    private String handleLogoutResponseFromFeide(HttpServletRequest request) throws SAML2Exception {
        /********************************************
         * We have got a LogoutResponse from IDP.
         ********************************************/
        String logoutResponseStr = request.getParameter(Constants.PARAMETER_SAMLRESPONSE);
        String relayState = request.getParameter(Constants.PARAMETER_RELAYSTATE);

        // Parse the response fra IDP
        SAMLLogoutResponse samlLogoutResponse = SAML2Util.parseSAMLogoutResponse(logoutResponseStr);

        if (log.isDebugEnabled()) {
            log.debug("Parsed LogoutResponse:" + SAML2Util.dom2String(samlLogoutResponse.getDocument()));
        }

        return relayState;
    }


    private String startLogout(HttpServletRequest request) throws SAML2Exception {
        /****************************************************************
         * We want to start a SLO by sending a logout request to the IDP
         ****************************************************************/
        String relayState = request.getParameter("redirect");
        log.info("Start logout, redirect:" + relayState);

        ServletContext servletContext = request.getSession().getServletContext();
        IDPConf idpConfig = Common.getConfigIDP(servletContext);
        SPConf spConfig = Common.getConfigSP(servletContext);

        HttpSession session = request.getSession();

        String userId = (String)session.getAttribute(authenticationContext + FeideSAML2IdentityResolver.SESSION_IDENTITY_NAME);
        String domain = (String)session.getAttribute(authenticationContext + FeideSAML2IdentityResolver.SESSION_IDENTITY_DOMAIN);

        String logoutUrl = defaultUnAuthenticatedUrl;

        if (userId != null && domain != null) {
            DefaultIdentity identity = new DefaultIdentity();
            identity.setUserId(userId);
            identity.setDomain(domain);

            if (userSessionManager.userHasValidSession(identity)) {
                UserSession userSession = userSessionManager.getUserSession(identity);

                userSessionManager.removeUserSession(identity);

                session.removeAttribute(authenticationContext + FeideSAML2IdentityResolver.SESSION_IDENTITY_NAME);
                session.removeAttribute(authenticationContext + FeideSAML2IdentityResolver.SESSION_IDENTITY_DOMAIN);

                logoutUrl = SAML2Util.createSAMLLogoutRequest(idpConfig, spConfig, userSession.getSamlNameId(), userSession.getSamlSessionIndex(), relayState);
            }
        }

        log.info("Created SAML logout request, redirect to:" + logoutUrl);

        return logoutUrl;
    }

    private void avoidCaching(HttpServletResponse response) {
        // To avoid any form of caching
        response.setHeader("Pragma", "no-cache"); //HTTP/1.0 Proxy Servers
        response.setHeader("Cache-Control", "no-cache, no-store"); //HTTP/1.1 Proxy Servers
        response.setDateHeader("Expires", 0); // for Browsers
    }

    @Required
    public void setAuthenticationContext(String authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    @Required
    public void setDefaultUnAuthenticatedUrl(String defaultUnAuthenticatedUrl) {
        this.defaultUnAuthenticatedUrl = defaultUnAuthenticatedUrl;
    }
}
