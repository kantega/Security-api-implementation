package no.kantega.security.api.impl.kerberos;

import org.simplericity.serberuhs.KerberosSubjectConfiguration;
import org.simplericity.serberuhs.SpNego;
import org.simplericity.serberuhs.filter.KerberosFilterConfiguration;

import javax.servlet.FilterConfig;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Created by IntelliJ IDEA.
 * User: bjorsnos
 * Date: May 12, 2009
 * Time: 1:33:50 PM
 * To change this template use File | Settings | File Templates.
 */
public class KerberosFilter extends org.simplericity.serberuhs.filter.KerberosFilter {

    @Override
    public KerberosFilterConfiguration createConfiguration(FilterConfig filterConfig) {
        return new AksessKerberosConfiguration(filterConfig);
    }

}
