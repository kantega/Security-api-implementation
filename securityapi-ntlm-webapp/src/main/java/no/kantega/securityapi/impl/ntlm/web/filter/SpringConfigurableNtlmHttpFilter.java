package no.kantega.securityapi.impl.ntlm.web.filter;

import jcifs.Config;
import jcifs.http.NtlmHttpFilter;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;

import org.springframework.beans.factory.InitializingBean;


public class SpringConfigurableNtlmHttpFilter extends NtlmHttpFilter implements InitializingBean {
    private String domainController;
    private String domain;

    public void setDomainController(String domainController) {
        this.domainController = domainController;
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);    //To change body of overridden methods use File | Settings | File Templates.
    }

    

    public void afterPropertiesSet() throws Exception {
        Config.setProperty("jcifs.http.domainController", domainController);
        Config.setProperty("jcifs.smb.client.domain", domain);
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }
}
