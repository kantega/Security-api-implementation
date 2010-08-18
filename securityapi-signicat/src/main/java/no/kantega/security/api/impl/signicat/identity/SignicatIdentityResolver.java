package no.kantega.security.api.impl.signicat.identity;

import com.signicat.services.client.ScResponseException;
import com.signicat.services.client.ScSecurityException;
import com.signicat.services.client.saml.SamlFacade;
import com.signicat.services.client.saml.SamlFacadeFactory;
import no.kantega.commons.log.Log;
import no.kantega.security.api.identity.*;
import no.kantega.security.api.impl.signicat.SignicatConfiguration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Date: Feb 9, 2010
 * Time: 12:12:41 AM
 *
 * @author Tarje Killingberg
 */
public class SignicatIdentityResolver implements IdentityResolver {

    private static final String SOURCE = SignicatIdentityResolver.class.getSimpleName();
    private static final String SESSION_ATTR_IDENTITY = "identity";
    private static final String SIGNICAT_PARAM_DEBUG = "debug";
    private static final String SIGNICAT_PARAM_TRUSTED_CERTIFICATE = "asserting.party.certificate.subject.dn";
    private static final String SIGNICAT_PARAM_TIME_SKEW = "time.skew";
    public static final String REQUEST_URL = "SignicatIdentityResolver_RequestUrl";

    private String authenticationContext;
    private String authenticationContextDescription;
    private String authenticationContextIconUrl;
    private SignicatConfiguration configuration;


    public AuthenticatedIdentity getIdentity(HttpServletRequest request) throws IdentificationFailedException {
        HttpSession session = request.getSession();
        AuthenticatedIdentity identity = (AuthenticatedIdentity)session.getAttribute(SESSION_ATTR_IDENTITY);
        if (identity == null) {
            // Identity was not stored in session. See if the request contains a valid SAMLResponse.
            String assertion = request.getParameter("SAMLResponse");
            if (assertion != null && assertion.length() > 0) {
                try {
                    identity = parseAssertion(assertion, request);
                    session.setAttribute(SESSION_ATTR_IDENTITY, identity);
                } catch (ScResponseException e) {
                    Log.error(SOURCE, e, null, null);
                    throw new IdentificationFailedException(SOURCE, "ERROR: The user was not authenticated.");
                } catch (ScSecurityException e) {
                    Log.error(SOURCE, e, null, null);
                    throw new IdentificationFailedException(SOURCE, "ERROR: The login was aborted.");
                } catch (MalformedURLException e) {
                    Log.error(SOURCE, e, null, null);
                    throw new IdentificationFailedException(SOURCE, "ERROR: The login failed.");
                }
            }
        }
        return identity;
    }

    @SuppressWarnings("unchecked")
    private AuthenticatedIdentity parseAssertion(String assertion, HttpServletRequest request) throws ScResponseException, ScSecurityException, MalformedURLException {
        Properties props = new Properties();
        props.setProperty(SIGNICAT_PARAM_DEBUG, Boolean.toString(configuration.isDebug()));
        props.setProperty(SIGNICAT_PARAM_TRUSTED_CERTIFICATE, configuration.getTrustedCertificate());
        if (configuration.getTimeSkew() != 0) {
            props.setProperty(SIGNICAT_PARAM_TIME_SKEW, Integer.toString(configuration.getTimeSkew()));
        }

        SamlFacadeFactory factory = new SamlFacadeFactory(props);
        SamlFacade samlFacade = factory.createSamlFacade();
        Map attributes = samlFacade.readAssertion(assertion, getRequestUrl(request));

        DefaultAuthenticatedIdentity identity = new DefaultAuthenticatedIdentity(this);
        identity.setDomain(authenticationContext);
        List userIdList = (List)attributes.get(configuration.getUserIdAttribute());
        if (userIdList != null && userIdList.size() > 0) {
            identity.setUserId((String)userIdList.get(0));
        }
        Properties p = new Properties();
        p.putAll(attributes);
        identity.setRawAttributes(p);
        return identity;
    }

    public void initateLogin(LoginContext loginContext) {
        String targetUrl = loginContext.getTargetUri().toString();
        try {
            loginContext.getResponse().sendRedirect(configuration.getLoginUrl() + targetUrl);
        } catch (IOException e) {
            Log.error(SOURCE, e, null, null);
        }
    }

    public void initiateLogout(LogoutContext logoutContext) {
        logoutContext.getRequest().getSession().removeAttribute(SESSION_ATTR_IDENTITY);
        if (logoutContext.getTargetUri() != null) {
            try {
                logoutContext.getResponse().sendRedirect(logoutContext.getTargetUri().toString());
            } catch (IOException e) {
                throw new RuntimeException("Could not redirect to url " + logoutContext.getTargetUri(), e);
            }
        }
    }

    public String getAuthenticationContext() {
        return authenticationContext;
    }

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

    public void setConfiguration(SignicatConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * Returns the URL of the requested service. If the application requires a specific request
     * URL this may be set in the defined attribute SignicatIdentityResolver.REQUEST_URL in the request.
     * @param request
     * @return
     * @throws MalformedURLException
     */
    private URL getRequestUrl(HttpServletRequest request) throws MalformedURLException {
        URL specificRequestUrl = null;
        try{
            specificRequestUrl = (URL) request.getAttribute(REQUEST_URL);
        }
        catch(Exception e){

        }

        if (specificRequestUrl!=null){
            return specificRequestUrl;
        }

        String url = request.getRequestURL().toString();
        String originalUri = (String)request.getAttribute("javax.servlet.error.request_uri");
        if (originalUri != null) {
            // Call via 404
            int port = request.getServerPort();
            String scheme = request.getScheme();
            String portStr = "";
            if (("http".equals(scheme) && port != 80) || ("https".equals(scheme) && port != 443)) {
                portStr = ":" + port;
            }
            url = scheme + "://" + request.getServerName() + portStr + originalUri;
        }

        String query = request.getQueryString();
        if (query != null && query.length() > 0) {
            url += "?" + query;
        }
        return new URL(url);
    }

}
