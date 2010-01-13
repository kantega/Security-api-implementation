package no.kantega.security.api.impl.kerberos;

import no.kantega.security.api.identity.*;

import javax.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.io.IOException;
import java.util.Properties;

import org.simplericity.serberuhs.filter.KerberosFilter;

/**
 * Created by IntelliJ IDEA.
 * User: bjorsnos
 * Date: May 12, 2009
 * Time: 12:58:23 PM
 * To change this template use File | Settings | File Templates.
 */
public class KerberosIdentityResolver implements IdentityResolver {

    private static final String DEFAULT_TARGET_URI_PARAM = "targetUri";

    private String authenticationContext = "kerberos";
    private String kerberosUrl;

    private String targetUrlParam = DEFAULT_TARGET_URI_PARAM;

    public AuthenticatedIdentity getIdentity(HttpServletRequest request) throws IdentificationFailedException {

        final String authorizedPrincipal = (String) request.getSession().getAttribute(KerberosFilter.AUTORIZED_PRINCIPAL_SESSION_ATTRIBUTE);
        return authorizedPrincipal == null ? null : new KerberosIdentity(this, authorizedPrincipal);
    }

    public void initateLogin(LoginContext loginContext) {
        String targetUri = loginContext.getTargetUri().toString();
        if(targetUri == null) {
            HttpServletRequest request = loginContext.getRequest();
            targetUri = request.getRequestURL().toString();
        }
        String authenticationService = kerberosUrl.startsWith("/") ? loginContext.getRequest().getContextPath() + kerberosUrl : kerberosUrl;

        String redirectUrl = null;
        try {
            redirectUrl = authenticationService +"?" + targetUrlParam +"=" + URLEncoder.encode(targetUri, "utf-8");
            loginContext.getResponse().sendRedirect(redirectUrl);
        } catch (IOException e) {
            throw new RuntimeException("Exception redirecting to uri " + redirectUrl, e);
        }
    }

    public void initiateLogout(LogoutContext logoutContext) {
        logoutContext.getRequest().getSession().removeAttribute(KerberosFilter.AUTORIZED_PRINCIPAL_SESSION_ATTRIBUTE);
        String targetUrl = "/";
        if (logoutContext.getTargetUri() != null) {
            targetUrl = logoutContext.getTargetUri().toASCIIString();
            targetUrl = targetUrl.replaceAll("<", "");
            targetUrl = targetUrl.replaceAll(">", "");
        }

        try {
            logoutContext.getResponse().sendRedirect(targetUrl);
        } catch (IOException e) {

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

    public void setAuthenticationContext(String authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    public void setKerberosUrl(String kerberosUrl) {
        this.kerberosUrl = kerberosUrl;
    }

    public void setTargetUrlParam(String targetUrlParam) {
        this.targetUrlParam = targetUrlParam;
    }

    private class KerberosIdentity implements AuthenticatedIdentity {
        private final IdentityResolver identityResolver;
        private final String authorizedPrincipal;

        public KerberosIdentity(KerberosIdentityResolver kerberosIdentityResolver, String authorizedPrincipal) {
            this.identityResolver = kerberosIdentityResolver;
            this.authorizedPrincipal = authorizedPrincipal;
        }

        public String getLanguage() {
            throw new IllegalStateException("Language not implemented");
        }

        public Properties getRawAttributes() {
            throw new IllegalStateException("Raw properties not implemented");
        }

        public IdentityResolver getResolver() {
            return identityResolver;
        }

        public String getUserId() {
            return authorizedPrincipal.substring(0, authorizedPrincipal.indexOf("@"));
        }

        public String getDomain() {
            return identityResolver.getAuthenticationContext();
        }
    }
}
