package no.kantega.security.api.saml;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.exception.Error;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.exception.XMLEntityException;
import com.onelogin.saml2.servlet.ServletUtils;
import com.onelogin.saml2.settings.Saml2Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class SamlServlet extends HttpServlet {
    private static Logger log = LoggerFactory.getLogger(SamlServlet.class);

    static final String AUTORIZED_PRINCIPAL_SESSION_ATTRIBUTE = "SAML_AUTORIZED_PRINCIPAL_SESSION_ATTRIBUTE";

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String path = "";
            log.debug("service {}", path);
            if ("login".equals(path)) {
                handleLogin(request, response);
            } else if ("metadata".equals(path)) {
                handleMetadata(request, response);
            } else if ("logout".equals(path)) {
                handleLogout(request, response);
            } else if("sls".equals("path")) {
                handleLogout(request, response);
            } else if("acs".equals(path)) {
                handleACS(request, response);
            }

        } catch (Exception e) {
           throw new RuntimeException(e);
        }

    }

    private void handleACS(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Auth auth = new Auth(config(), request, response);
        auth.processResponse();

        if (!auth.isAuthenticated()) {
            response.sendError(403, "Not authenticated");
        } else {
            Map<String, List<String>> attributes = auth.getAttributes();

            List<String> ident = attributes.get("Ident");
            // TODO assert size
            request.getSession().setAttribute(AUTORIZED_PRINCIPAL_SESSION_ATTRIBUTE, ident.get(0));
            String relayState = request.getParameter("RelayState");

            if (relayState != null && !relayState.isEmpty() && !relayState.equals(ServletUtils.getSelfRoutedURLNoQuery(request)) &&
                    !relayState.contains("/login")) { // We don't want to be redirected to login.jsp neither
                response.sendRedirect(request.getParameter("RelayState"));
            }
        }

        List<String> errors = auth.getErrors();

        if (!errors.isEmpty()) {
            log.error("{}", errors);
            if (auth.isDebugActive()) {
                String errorReason = auth.getLastErrorReason();
                if (errorReason != null && !errorReason.isEmpty()) {
                    log.debug(errorReason);
                }
            }
        }
    }

    private void handleLogout(HttpServletRequest request, HttpServletResponse response) throws SettingsException, Error, IOException, XMLEntityException {
        Auth auth = new Auth(config(), request, response);
        HttpSession session = request.getSession();
        String nameId = null;
        if (session.getAttribute("nameId") != null) {
            nameId = session.getAttribute("nameId").toString();
        }
        String nameIdFormat = null;
        if (session.getAttribute("nameIdFormat") != null) {
            nameIdFormat = session.getAttribute("nameIdFormat").toString();
        }
        String nameidNameQualifier = null;
        if (session.getAttribute("nameidNameQualifier") != null) {
            nameIdFormat = session.getAttribute("nameidNameQualifier").toString();
        }
        String nameidSPNameQualifier = null;
        if (session.getAttribute("nameidSPNameQualifier") != null) {
            nameidSPNameQualifier = session.getAttribute("nameidSPNameQualifier").toString();
        }
        String sessionIndex = null;
        if (session.getAttribute("sessionIndex") != null) {
            sessionIndex = session.getAttribute("sessionIndex").toString();
        }
        auth.logout(null, nameId, sessionIndex, nameIdFormat, nameidNameQualifier, nameidSPNameQualifier);
    }

    private void handleMetadata(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Auth auth = new Auth();
        Saml2Settings settings = auth.getSettings();
        settings.setSPValidationOnly(true);
        String metadata = settings.getSPMetadata();
        List<String> errors = Saml2Settings.validateMetadata(metadata);
        if (errors.isEmpty()) {
            response.getWriter().println(metadata);
        } else {
            response.setContentType("text/html; charset=UTF-8");

            for (String error : errors) {
                response.getWriter().println("<p>"+error+"</p>");
            }
        }

    }

    private void handleLogin(HttpServletRequest request, HttpServletResponse response) throws SettingsException, Error, IOException {
        Auth auth = new Auth(config(), request, response);
        if (request.getParameter("attrs") == null) {
            auth.login();
        } else {
            auth.login(request.getContextPath() + "/attrs.jsp");
        }
    }

    private String config() {
        return getInitParameter("saml.config.file");
    }

}
