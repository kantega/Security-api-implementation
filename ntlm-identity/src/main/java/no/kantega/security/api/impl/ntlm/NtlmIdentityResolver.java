package no.kantega.security.api.impl.ntlm;

import jcifs.smb.NtlmPasswordAuthentication;
import no.kantega.security.api.identity.*;
import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import java.util.Properties;


public class NtlmIdentityResolver implements IdentityResolver {

    private static final String NTML_REQUEST_ATTR = "NtlmHttpAuth";
    private String authenticationContext = "ntlm";
    private Logger log = Logger.getLogger(getClass());

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
        throw new IllegalStateException("NTLM authentication is not supposed to be initialized, it should be automatic");
    }

    public void initiateLogout(LogoutContext logoutContext) {
        throw new IllegalStateException("NTLM logout is not supported");
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
            return ntlmAuthentication.getDomain();
        }
    }
}
