package no.kantega.security.api.impl.signicat.identity;

import com.signicat.services.client.ScResponseException;
import com.signicat.services.client.ScSecurityException;
import com.signicat.services.client.saml.SamlFacade;
import com.signicat.services.client.saml.SamlFacadeFactory;
import no.kantega.commons.log.Log;
import no.kantega.security.api.identity.*;

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
public class BankIdIdentityResolver implements IdentityResolver {

    private static final String SOURCE = BankIdIdentityResolver.class.getSimpleName();
    private static final String IDENTITY = "identity";
    private static final String TRUSTED_CERTIFICATE_NAME = "asserting.party.certificate.subject.dn";

    private String authenticationContext;
    private String authenticationContextDescription;
    private String authenticationContextIconUrl;
    private String loginUrl;
    private String userIdAttribute = "saml.attribute.bankid.certificate.subject-dn";
    /* The name of the certificate we trust. */
    private String trustedCertificate;


    public AuthenticatedIdentity getIdentity(HttpServletRequest request) throws IdentificationFailedException {
        HttpSession session = request.getSession();
        AuthenticatedIdentity identity = (AuthenticatedIdentity)session.getAttribute(IDENTITY);
        if (identity == null) {
            // Identity was not stored in session. See if the request contains a valid SAMLResponse.
            String assertion = request.getParameter("SAMLResponse");
            if (assertion != null && assertion.length() > 0) {
                try {
                    identity = parseAssertion(assertion, request);
                    session.setAttribute(IDENTITY, identity);
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
        Properties configuration = new Properties();
        configuration.setProperty("debug", "false");
        configuration.setProperty(TRUSTED_CERTIFICATE_NAME, trustedCertificate);

        SamlFacadeFactory factory = new SamlFacadeFactory(configuration);
        SamlFacade samlFacade = factory.createSamlFacade();
        Map attributes = samlFacade.readAssertion(assertion, getRequestUrl(request));

        DefaultAuthenticatedIdentity identity = new DefaultAuthenticatedIdentity(this);
        identity.setDomain(authenticationContext);
        List userIdList = (List)attributes.get(userIdAttribute);
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
            loginContext.getResponse().sendRedirect(loginUrl + targetUrl);
        } catch (IOException e) {
            Log.error(SOURCE, e, null, null);
        }
    }

    public void initiateLogout(LogoutContext logoutContext) {
        logoutContext.getRequest().getSession().removeAttribute(IDENTITY);
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

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public void setTrustedCertificate(String trustedCertificate) {
        this.trustedCertificate = trustedCertificate;
    }

    private URL getRequestUrl(HttpServletRequest request) throws MalformedURLException {
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
