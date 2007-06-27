package no.kantega.security.api.impl.feide.identity;

import no.kantega.security.api.identity.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.servlet.http.Cookie;
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Properties;
import java.util.Enumeration;

import com.iplanet.sso.SSOTokenManager;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;

/**
 * User: Anders Skar, Kantega AS
 * Date: May 21, 2007
 * Time: 2:02:43 PM
 */
public class FeideIdentityResolver implements IdentityResolver {
    public static String SESSION_IDENTITY_NAME = "KANTEGA_FEIDE_IDENTITY";
    private static String SOURCE = "FeideIdentityResolver";

    private String authenticationContext;
    private String authenticationContextDescription = "FeideID";
    private String authenticationContextIconUrl = "";
    private String loginPageUrl = "";
    private String logoutPageUrl = "";
    private String cookieName = "iPlanetDirectoryPro";
    private String usernameAttribute = "eduPersonPrincipalName";



    public AuthenticatedIdentity getIdentity(HttpServletRequest request) throws IdentificationFailedException {
        DefaultAuthenticatedIdentity identity = null;

        HttpSession session = request.getSession();
        if (session == null) {
            return null;
        }

        SSOTokenManager manager;

        try {
            manager = SSOTokenManager.getInstance();
        } catch (SSOException e) {
            throw new IdentificationFailedException(SOURCE, "SSOException:" + e);
        }

        String tokenId = null;
        try {
            tokenId = getDecodedTokenID(request.getCookies());
        } catch (UnsupportedEncodingException e) {
            throw new IdentificationFailedException(SOURCE, "UnsupportedEncodingException:" + e);
        }

        if (tokenId != null) {
            System.out.println(SOURCE + ": Got tokenId");

            SSOToken ssoToken = null;

            try {
                ssoToken = manager.createSSOToken(tokenId);

                if (ssoToken != null && manager.isValidToken(ssoToken)) {
                    System.out.println(SOURCE + ": Got valid token");

                    // Bruker er logget inn med gyldig token
                    Properties rawAttributes = getAttributes(ssoToken);
                    String userId = rawAttributes.getProperty(usernameAttribute);
                    if (userId != null) {
                        identity = new DefaultAuthenticatedIdentity(this);
                        identity.setRawAttributes(rawAttributes);
                        identity.setUserId(userId);
                    } else {
                        System.out.println(SOURCE + ": UserId not found, looking for:" + userId);
                    }
                }
            } catch (SSOException e) {
                e.printStackTrace();
                throw new IdentificationFailedException(SOURCE, "SSOException:" + e);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
                throw new IdentificationFailedException(SOURCE, "UnsupportedEncodingException:" + e);
            }
        } else {
            System.out.println(SOURCE + ": No tokenid");
        }

        return identity;
    }

    public void initateLogin(LoginContext loginContext) {
        String targetUrl = "/";
        if (loginContext.getTargetUri() != null) {
            targetUrl = loginContext.getTargetUri().toASCIIString();
            targetUrl = targetUrl.replaceAll("<", "");
            targetUrl = targetUrl.replaceAll(">", "");
        }

        String redirectUrl;
        if (loginPageUrl.indexOf("?") > 0) {
            redirectUrl = loginPageUrl + "&RelayState=";
        } else {
            redirectUrl = loginPageUrl + "?RelayState=";
        }

        try {
            System.out.println(SOURCE + ": Send redirect to: " + redirectUrl);
            loginContext.getResponse().sendRedirect(redirectUrl + URLEncoder.encode(targetUrl, "UTF-8"));
        } catch (IOException e) {
            //
        }
    }


    public void initiateLogout(LogoutContext logoutContext) {
        HttpSession session = logoutContext.getRequest().getSession();
        if (session != null) {
            session.removeAttribute(authenticationContext + SESSION_IDENTITY_NAME);
        }

        String targetUrl = "/";
        if (logoutContext.getTargetUri() != null) {
            targetUrl = logoutContext.getTargetUri().toASCIIString();
            targetUrl = targetUrl.replaceAll("<", "");
            targetUrl = targetUrl.replaceAll(">", "");
        }

        String redirectUrl;
        if (logoutPageUrl.indexOf("?") > 0) {
            redirectUrl = logoutPageUrl + "&redirect=";
        } else {
            redirectUrl = logoutPageUrl + "?redirect=";
        }

        try {
            logoutContext.getResponse().sendRedirect(redirectUrl + URLEncoder.encode(targetUrl, "UTF-8"));
        } catch (IOException e) {
            //
        }
    }


    private String getDecodedTokenID(Cookie[] cookies) throws UnsupportedEncodingException {

        if (cookies == null) {
            return null;
        }

        // Find our token ID cookie's encoded value.
        String ssoTokenID = null;
        for (int i = 0; i < cookies.length; i++) {
            if (cookies[i].getName().equalsIgnoreCase(cookieName)) {
                ssoTokenID = cookies[i].getValue();
                break;
            }
        }

        if (ssoTokenID == null) {
            return null;
        }

        ssoTokenID = URLDecoder.decode(ssoTokenID, "ISO-8859-1");

        return ssoTokenID;
    }


    private Properties getAttributes(SSOToken ssoToken) throws SSOException, UnsupportedEncodingException {

        Properties properties = new Properties();

        String[] names = AttributeManager.getAvailableAttributes(ssoToken);
        for (int i = 0; i < names.length; i++) {
            String[] values = AttributeManager.getDecodedValues(ssoToken, names[i]);
            if (values != null && values.length > 0) {

                StringBuffer value = new StringBuffer();
                for (int j = 0; j < values.length; j++) {
                    if (j > 0) {
                        value.append(",");
                    }
                    value.append(values[j]);
                }

                System.out.println(SOURCE + ": adding:" + names[i] + ":" + value.toString());

                properties.setProperty(names[i], value.toString());
            }

        }

        return properties;
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

    public void setLoginPageUrl(String loginPageUrl) {
        this.loginPageUrl = loginPageUrl;
    }

    public void setLogoutPageUrl(String logoutPageUrl) {
        this.logoutPageUrl = logoutPageUrl;
    }

    public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }

    public void setUsernameAttribute(String usernameAttribute) {
        this.usernameAttribute = usernameAttribute;
    }
}
