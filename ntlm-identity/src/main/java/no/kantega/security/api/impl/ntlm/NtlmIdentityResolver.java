package no.kantega.security.api.impl.ntlm;

import jcifs.smb.NtlmPasswordAuthentication;
import no.kantega.security.api.identity.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.Properties;


public class NtlmIdentityResolver implements IdentityResolver {

    private static final String NTML_REQUEST_ATTR = "NtlmHttpAuth";
    private String authenticationContext = "ntlm";
    private Logger log = LoggerFactory.getLogger(getClass());
    private static final String TARGET_URI_PARAM = "targetUri";
    private String ntlmUrl;

    public AuthenticatedIdentity getIdentity(HttpServletRequest httpServletRequest) throws IdentificationFailedException {
        NtlmPasswordAuthentication auth = (NtlmPasswordAuthentication) httpServletRequest.getSession().getAttribute(NTML_REQUEST_ATTR);

        if(auth == null) {
            if(log.isDebugEnabled()) {
                log.debug("User is not authenticated throgh NTLM. Is this URL behind the NTLMHttpFilter");
            }
            return null;
        } else {
            return new NtlmAuthenticatedIdentity(this, auth);
        }
    }

    public void initateLogin(LoginContext loginContext) {
        String targetUri = loginContext.getTargetUri().toString();
        if(targetUri == null) {
            HttpServletRequest request = loginContext.getRequest();
            targetUri = request.getRequestURL().toString();
        }
        String authenticationService = ntlmUrl.startsWith("/") ? loginContext.getRequest().getContextPath() + ntlmUrl : ntlmUrl;
        
        String redirectUrl = null;
        try {
            redirectUrl = authenticationService +"?" + TARGET_URI_PARAM +"=" + URLEncoder.encode(targetUri, "utf-8");
            loginContext.getResponse().sendRedirect(redirectUrl);
        } catch (IOException e) {
            throw new RuntimeException("Exception redirecting to uri " + redirectUrl, e);
        }
    }

    public void initiateLogout(LogoutContext logoutContext) {
        logoutContext.getRequest().getSession().removeAttribute(NTML_REQUEST_ATTR);
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

    public void setNtlmUrl(String ntlmUrl) {
        this.ntlmUrl = ntlmUrl;
    }

    class NtlmAuthenticatedIdentity implements AuthenticatedIdentity {
        private IdentityResolver resolver;
        private NtlmPasswordAuthentication ntlmAuthentication;

        public NtlmAuthenticatedIdentity(IdentityResolver resolver, NtlmPasswordAuthentication ntlmAuthentication) {
            this.resolver = resolver;
            this.ntlmAuthentication = ntlmAuthentication;
        }

        public String getLanguage() {
            throw new IllegalStateException("Language not implemented");
        }

        public Properties getRawAttributes() {
            throw new IllegalStateException("Raw properties not implemented");
        }


        public IdentityResolver getResolver() {
            return resolver;
        }

        public String getUserId() {
            return ntlmAuthentication.getUsername();
        }

        public String getDomain() {
            return resolver.getAuthenticationContext();
        }
    }
}
