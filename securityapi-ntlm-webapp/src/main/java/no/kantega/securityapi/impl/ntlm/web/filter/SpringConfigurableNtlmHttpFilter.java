package no.kantega.securityapi.impl.ntlm.web.filter;

import jcifs.Config;
import jcifs.http.NtlmHttpFilter;
import org.springframework.beans.factory.InitializingBean;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import java.util.Properties;
import java.util.Enumeration;


public class SpringConfigurableNtlmHttpFilter extends NtlmHttpFilter implements InitializingBean {
    private Properties properties;


    public void init(FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);    //To change body of overridden methods use File | Settings | File Templates.
    }

    public void afterPropertiesSet() throws Exception {

        Enumeration e = properties.propertyNames();
        while (e.hasMoreElements()) {
            String name = (String) e.nextElement();
            if(name.startsWith("jcifs.")) {
                Config.setProperty(name, properties.getProperty(name));
            }
        }
    }

    public void setProperties(Properties properties) {
        this.properties = properties;
    }
}
