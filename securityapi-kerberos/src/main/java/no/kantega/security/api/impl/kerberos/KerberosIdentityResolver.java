package no.kantega.security.api.impl.kerberos;

import no.kantega.security.api.identity.*;
import org.simplericity.serberuhs.filter.KerberosFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.Properties;

public class KerberosIdentityResolver implements IdentityResolver {
    private static Logger log = LoggerFactory.getLogger(KerberosIdentityResolver.class);

    private static final String DEFAULT_TARGET_URI_PARAM = "targetUri";

    private String authenticationContext = "kerberos";
    private String kerberosUrl;

    private String targetUrlParam = DEFAULT_TARGET_URI_PARAM;

    public AuthenticatedIdentity getIdentity(HttpServletRequest request) throws IdentificationFailedException {

        final String authorizedPrincipal = (String) request.getSession().getAttribute(KerberosFilter.AUTORIZED_PRINCIPAL_SESSION_ATTRIBUTE);
        log.debug("authorizedPrincipal: {}", authorizedPrincipal);
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
