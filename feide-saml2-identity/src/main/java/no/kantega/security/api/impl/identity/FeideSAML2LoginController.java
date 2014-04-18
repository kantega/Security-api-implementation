package no.kantega.security.api.impl.identity;

import no.kantega.security.api.identity.DefaultIdentity;
import no.ntnu.it.fw.saml2api.*;
import no.ntnu.it.fw.saml2api.http.Common;
import org.eclipse.higgins.saml2idp.saml2.SAMLAssertion;
import org.eclipse.higgins.saml2idp.saml2.SAMLConstants;
import org.eclipse.higgins.saml2idp.saml2.SAMLResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class FeideSAML2LoginController extends AbstractFeideConfigurable implements Controller {
    private static Logger log = LoggerFactory.getLogger(FeideSAML2LoginController.class);

    private String authenticationContext;
    private String defaultUnAuthenticatedUrl;

    private UrlJumpTokenManager tokenManager;
    private UserSessionManager userSessionManager;

    public FeideSAML2LoginController() {
        tokenManager = new UrlJumpTokenManager();
        userSessionManager = new UserSessionManager();
    }

    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();

        init(session);

        String samlResponseArg = request.getParameter(Constants.PARAMETER_SAMLRESPONSE);

        UserSession userSession = null;
        if(samlResponseArg != null ){
            userSession = createUserSession(session, samlResponseArg);
        }

        if (userSession != null) {
            userSessionManager.saveUserSession(userSession);
            // We create a jump token to be able to redirect between sites, since we can't use SAML2API with multiple sites
            String token = tokenManager.createJumpToken(userSession.getIdentity());
            String relayState = request.getParameter("RelayState");
            if (relayState.contains("?")) {
                relayState = relayState + "&";
            } else {
                relayState = relayState + "?";
            }

            response.sendRedirect(relayState + FeideSAML2IdentityResolver.URL_JUMP_TOKEN + "=" + token);
            return null;
        }

        response.sendRedirect(defaultUnAuthenticatedUrl);
        return null;
    }

    private UserSession createUserSession(HttpSession session, String samlResponseArg) {
        try {
            return initiateUserSession(session, samlResponseArg);
        } catch (SAML2Exception e) {
            log.error("Could not create EduPerson");
        }

        return null;
    }

    private UserSession initiateUserSession(HttpSession session, String samlResponseArg) throws SAML2Exception {
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

        EduPerson eduPerson = SAML2Util.createEduPerson(samlAssertion, idpConfig.isAttribValuesBase64Encoded(), idpConfig.getFeideSplitChar());

        log.debug(eduPerson.dump());

        log.info("Authenticated as username:" + eduPerson.getUsername() + ", orgDN:" + eduPerson.getOrgDN());

        DefaultIdentity identity = new DefaultIdentity();
        identity.setUserId(eduPerson.getUsername());
        identity.setDomain(authenticationContext);

        UserSession userSession = new UserSession();
        userSession.setIdentity(identity);
        userSession.setSamlNameId(samlAssertion.getSubject().getNameID());
        userSession.setSamlSessionIndex(SAML2Util.parseSessionIndex(samlAssertion));

        return userSession;
    }

    @Required
    public void setDefaultUnAuthenticatedUrl(String defaultUnAuthenticatedUrl) {
        this.defaultUnAuthenticatedUrl = defaultUnAuthenticatedUrl;
    }

    @Required
    public void setAuthenticationContext(String authenticationContext) {
        this.authenticationContext = authenticationContext;
    }
}
