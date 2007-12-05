package no.kantega.securityapi.impl.ntlm.web;

import no.kantega.security.api.identity.AuthenticatedIdentity;
import no.kantega.security.api.identity.IdentificationFailedException;
import no.kantega.security.api.identity.IdentityResolver;
import no.kantega.security.api.impl.dbsession.dao.SessionStore;
import org.apache.log4j.Logger;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.net.URLEncoder;

public class LoginController extends AbstractController {
    private IdentityResolver identityResolver;
    private SessionStore store;
    private Logger log = Logger.getLogger(getClass());
    private String targetUri;
    private String identityKeyParam = "identityKey";


    protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            AuthenticatedIdentity identity = identityResolver.getIdentity(request);

            // This shouldn't happen if this url is protected by NTLM filter.
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

            String redirectUrl = targetUri + "?" + identityKeyParam +"=" + URLEncoder.encode(key, "utf-8");
            if(log.isDebugEnabled()) {
                log.info("Redirecting user to url " + redirectUrl);
            }
            return new ModelAndView(new RedirectView(targetUri), identityKeyParam, URLEncoder.encode(key, "utf-8"));
        } catch (IdentificationFailedException e) {
            log.error("Identification of request failed width exception", e);
            response.getWriter().write("Identification failed");
            return null;
        }
    }

    public void setTargetUri(String targetUri) {
        this.targetUri = targetUri;
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
