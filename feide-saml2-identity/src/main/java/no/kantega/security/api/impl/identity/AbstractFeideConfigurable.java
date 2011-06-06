package no.kantega.security.api.impl.identity;

import no.ntnu.it.fw.saml2api.ConfigurationException;
import no.ntnu.it.fw.saml2api.IDPConf;
import no.ntnu.it.fw.saml2api.SPConf;
import no.ntnu.it.fw.saml2api.http.Common;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Required;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;

public abstract class AbstractFeideConfigurable {
    private static Logger log = Logger.getLogger(AbstractFeideConfigurable.class);

    private String spConfFilePath;
    private boolean isConfigured = false;

    protected void init(HttpSession session) {
        if (isConfigured) {
            return;
        }

        if(session == null){
            throw new IllegalArgumentException("Session was null");
        }
        ServletContext servletContext = session.getServletContext();
        try {
            String fullspConfFilePath = checkContextPath(spConfFilePath, servletContext);
            SPConf spConf =  new SPConf(fullspConfFilePath);

            String idpConfFile = checkContextPath(spConf.getIdpConfFile(), servletContext);

            IDPConf idpConf = new IDPConf(idpConfFile);

            Common.setConfigIDP(servletContext, idpConf);
            Common.setConfigSP(servletContext, spConf);
        } catch (ConfigurationException e) {
            log.error("Error when initializing", e);
        }

        isConfigured = true;
    }

    /**
     * If the path starts with /WEB-INF/ it is asumed that the file is in the context and
     * the real context path is returned.
     * @param path Path of the file - can not be null.
     * @return Return File path string
     */
    private String checkContextPath(String path, ServletContext servletContext){
        if (path.startsWith("/WEB-INF/")){
            path = servletContext.getRealPath(path);
        }
        return path;
    }

    @Required
    public void setSpConfFilePath(String spConfFilePath) {
        this.spConfFilePath = spConfFilePath;
    }
}
