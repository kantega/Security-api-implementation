package no.kantega.securityapi.impl.ntlm.web;

import no.kantega.security.api.identity.AuthenticatedIdentity;
import no.kantega.security.api.identity.IdentificationFailedException;
import no.kantega.security.api.identity.IdentityResolver;
import no.kantega.security.api.impl.dbsession.dao.SessionStore;
import org.apache.log4j.Logger;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.net.URLEncoder;

public class LoginController extends AbstractController {
    private IdentityResolver identityResolver;
    private SessionStore store;
    private Logger log = Logger.getLogger(getClass());
    private String loginUri;
    private String identityKeyParam = "identityKey";
    private static final String TARGET_URI_PARAM = "targetUri";


    protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            AuthenticatedIdentity identity = identityResolver.getIdentity(request);

            // Verify that we are protected by the NTLM filter
            if(identity == null) {
                log.error(identityResolver.getClass().getName() + " returned null for request. Is this url protected with NTLM?");
                PrintWriter out = response.getWriter();
                out.write("Identification failed. See log for details");
                out.flush();
                out.close();
                return null;
            }

            // Ok, let's store the user in the store and redirect user back with the key
            String userId = identity.getUserId();
            String key = store.storeSession(userId);

            log.info("User with username " + userId +" was saved in store with key " + key);
            String targetUri = request.getParameter(TARGET_URI_PARAM);

            String redirectUrl = loginUri + "?" + identityKeyParam +"=" + URLEncoder.encode(key, "utf-8");
            if(targetUri != null) {
                redirectUrl += "&" +TARGET_URI_PARAM +"=" +URLEncoder.encode(targetUri, "utf-8"); 
            }
            if(log.isDebugEnabled()) {
                log.info("Redirecting user to url " + redirectUrl);
            }
            response.sendRedirect(redirectUrl.toString());
            return null;
        } catch (IdentificationFailedException e) {
            log.error("Identification of request failed width exception", e);
            response.getWriter().write("Identification failed");
            return null;
        }
    }

    public void setLoginUri(String loginUri) {
        this.loginUri = loginUri;
    }

    public void setIdentityKeyParam(String identityKeyParam) {
        this.identityKeyParam = identityKeyParam;
    }

    public void setIdentityResolver(IdentityResolver identityResolver) {
        this.identityResolver = identityResolver;
    }

    public void setStore(SessionStore store) {
        this.store = store;
    }
}
