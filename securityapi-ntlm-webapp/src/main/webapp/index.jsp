<%@ page import="no.kantega.security.api.identity.IdentityResolver" %>
<%@ page import="org.springframework.web.context.WebApplicationContext" %>
<%@ page import="org.springframework.web.context.support.WebApplicationContextUtils" %>
<html>
<body>
<!--
<h2>Hello World!</h2>
<form method="post">
    <input name="name" value="JohnDoe">
    <input type="submit">
</form>-->

<%
    WebApplicationContext applicationContext = WebApplicationContextUtils.getRequiredWebApplicationContext(config.getServletContext());
    IdentityResolver resolver = (IdentityResolver) applicationContext.getBean("ntlmIdentityResolver", IdentityResolver.class);
%>

Logged in as <%=resolver.getIdentity(request).getUserId()%>
</body>
</html>
