package no.kantega.security.api.impl.kerberos;

import org.simplericity.serberuhs.SpNego;
import org.simplericity.serberuhs.filter.KerberosFilterConfiguration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.FilterConfig;
import java.io.IOException;

import static no.kantega.publishing.common.Aksess.getConfiguration;

/**
 */
public class TestKerberosFilter extends KerberosFilter {
    private FilterConfig filterConfig;


    protected void handleMissingAuthorizationHeader(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        try {
            req.getRequestDispatcher(getConfiguration().getString("kerberos.test.missing")).include(req, res);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected void handleUnsuccessfulAutorization(SpNego spNego, HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        try {
            req.getRequestDispatcher(getConfiguration().getString("kerberos.test.unsuccess")).include(req, res);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected void handleSuccessfulAuthorization(String authorizedPrincipal, HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        try {
            req.getRequestDispatcher(getConfiguration().getString("kerberos.test.ok")).include(req, res);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}