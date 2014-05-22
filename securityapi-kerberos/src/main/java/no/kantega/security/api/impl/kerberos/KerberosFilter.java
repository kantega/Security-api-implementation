package no.kantega.security.api.impl.kerberos;

import org.simplericity.serberuhs.filter.KerberosFilterConfiguration;

import javax.servlet.FilterConfig;

public class KerberosFilter extends org.simplericity.serberuhs.filter.KerberosFilter {

    @Override
    public KerberosFilterConfiguration createConfiguration(FilterConfig filterConfig) {
        return new AksessKerberosConfiguration(filterConfig);
    }

}
