<%@ page import="no.kantega.security.api.impl.feide.identity.FeideIdentityResolver"%>
<%@ page import="java.net.URI"%>
<%@ page import="no.kantega.security.api.identity.DefaultLoginContext"%>
<%@ page import="no.kantega.security.api.identity.AuthenticatedIdentity"%>
<%
    FeideIdentityResolver resolver = new FeideIdentityResolver();
    resolver.setLoginPageUrl("https://sbtest.kantega.no:1443/federation/spssoinit?metaAlias=%2Fsp&idpEntityID=sam.feide.no&AuthnContextClassRef=Password&binding=HTTP-POST&NameIDFormat=transient");
    resolver.setLogoutPageUrl("https://sam.feide.no/amserver/saml2/jsp/idpSingleLogoutInit.jsp?binding=urn:oasis:names:tc:SAML:2.0:bindings:SOAP");
    resolver.setAuthenticationContext("feide");

    AuthenticatedIdentity identity = resolver.getIdentity(request);
    if (identity == null) {
        System.out.println("User not logged in, initiate login");
        DefaultLoginContext loginContext = new DefaultLoginContext();

        loginContext.setRequest(request);
        loginContext.setResponse(response);
        loginContext.setTargetUri(new URI("https://sbtest.kantega.no/sampleapp/feide.jsp"));
        resolver.initateLogin(loginContext);
    } else {
        System.out.println("User is logged in");
        response.sendRedirect("feide.jsp");
    }

%>
(END)