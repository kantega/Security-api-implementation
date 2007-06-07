<%@ page import="no.kantega.security.api.impl.feide.identity.FeideIdentityResolver"%>
<%@ page import="no.kantega.security.api.identity.AuthenticatedIdentity"%>
<%
    FeideIdentityResolver resolver = new FeideIdentityResolver();
    resolver.setLoginPageUrl("https://sbtest.kantega.no:1443/federation/spssoinit?metaAlias=%2Fsp&amp;idpEntityID=sam.feide.no&amp;AuthnContextClassRef=Password&amp;binding=HTTP-POST&amp;NameIDFormat=transient");
    resolver.setLogoutPageUrl("https://sam.feide.no/amserver/saml2/jsp/idpSingleLogoutInit.jsp?binding=urn:oasis:names:tc:SAML:2.0:bindings:SOAP");
    resolver.setAuthenticationContext("feide");

    AuthenticatedIdentity identity = resolver.getIdentity(request);
    if (identity == null) {
        out.write("identity == NULL");
        System.out.println("Identity == NULL");
    } else {
        out.write("Feide userId:" + identity.getUserId());
        System.out.println("Feide userId:" + identity.getUserId());
    }
%>