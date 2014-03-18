package no.kantega.security.api.impl.ntlm.filter;

import jcifs.http.NtlmHttpFilter;
import no.kantega.publishing.common.Aksess;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import java.util.Enumeration;
import java.util.Properties;


public class AksessConfigurableNTLMHttpFilter extends NtlmHttpFilter {

    @Override
    public void init(final FilterConfig filterConfig) throws ServletException {

        final Properties prop;

        prop = Aksess.getConfiguration().getProperties();

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
