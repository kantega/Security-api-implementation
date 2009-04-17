package no.kantega.security.api.impl.ntlm.filter;

import jcifs.http.NtlmHttpFilter;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import java.util.Enumeration;
import java.util.Properties;
import java.io.IOException;
import java.io.File;

import no.kantega.commons.configuration.Configuration;
import no.kantega.commons.exception.ConfigurationException;
import no.kantega.publishing.common.Aksess;
import org.springframework.core.io.FileSystemResource;


public class AksessConfigurableNTLMHttpFilter extends NtlmHttpFilter {

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {

        final Properties prop = new Properties();

        File confFile = null;
        try {
            confFile = new File(Configuration.getConfigDirectory(), "aksess.conf");
            prop.load(new FileSystemResource(confFile).getInputStream());
        } catch (IOException e) {
            throw new ServletException("Can't read configuration properties from aksess.conf" + confFile, e);
        } catch (ConfigurationException e) {
            throw new ServletException("Can't read configuration properties from aksess.conf" + confFile, e);
        }

        FilterConfig wrapper = new FilterConfig() {
            public String getFilterName() {
                return filterConfig.getFilterName();
            }

            public ServletContext getServletContext() {
                return filterConfig.getServletContext();
            }

            public String getInitParameter(String name) {
                return prop.getProperty(name);
            }

            public Enumeration getInitParameterNames() {
                return prop.propertyNames();
            }
        };
        super.init(wrapper);
    }
}
