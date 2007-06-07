 package no.kantega.security.api.impl.xmluser.role;

import no.kantega.security.api.impl.xmluser.XMLUserManagerConfigurable;
import no.kantega.security.api.role.*;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.search.SearchResult;
import no.kantega.security.api.search.DefaultSearchResult;
import no.kantega.security.api.identity.Identity;

import java.util.*;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import org.apache.xpath.XPathAPI;

import javax.xml.transform.TransformerException;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jun 5, 2007
 * Time: 9:48:30 AM
 */
public class XMLUserRoleManager extends XMLUserManagerConfigurable implements RoleManager {
    private static final String ROLES_MEMBER_ATTRIBUTE = "roles";
    private static final String ROLEID_ATTRIBUTE = "rolename";
    private static final String ROLENAME_ATTRIBUTE = "description";

    public Iterator getAllRoles() throws SystemException {
        return searchRoles(null).getAllResults();
    }


    public SearchResult searchRoles(String name) throws SystemException {
        DefaultSearchResult searchResult = new DefaultSearchResult();

        List roles = new ArrayList();

        Document usersdoc = null;
        try {
            usersdoc = getUserPasswordFileAsXMLDocument();
        } catch (Exception e) {
            throw new SystemException("Error opening XML users file:" + getXmlUsersFilename(), e);
        }

        try {
            NodeList lstRoles = XPathAPI.selectNodeList(usersdoc.getDocumentElement(), "role");
            for (int i = 0; i < lstRoles.getLength(); i++) {
                Element elmRole = (Element)lstRoles.item(i);
                String roleId = elmRole.getAttribute(ROLEID_ATTRIBUTE);
                if (roleId != null) {
                    String roleName = elmRole.getAttribute(ROLENAME_ATTRIBUTE);
                    if (roleName == null || roleName.length() == 0) {
                        roleName = roleId;
                    }

                    DefaultRole role = new DefaultRole();
                    role.setId(roleId);
                    role.setName(roleName);
                    role.setDomain(domain);

                    roles.add(role);
                }
            }
        } catch (Exception e) {
            throw new SystemException("Error processing XML users file:" + getXmlUsersFilename(), e);
        }

        // Sorter lista basert på navn på rolle
        Comparator comparator = new RoleComparator();
        Collections.sort(roles, comparator);

        searchResult.setResults(roles);

        return searchResult;
    }


    public Role getRoleById(RoleId roleId) throws SystemException {
        Iterator allRoles = getAllRoles();
        while (allRoles.hasNext()) {
            Role role = (Role)allRoles.next();
            if (role.getId().equalsIgnoreCase(roleId.getId()) && role.getDomain().equalsIgnoreCase(roleId.getDomain())) {
                return role;
            }
        }

        return null;
    }


    public Iterator getRolesForUser(Identity identity) throws SystemException {
        List roles = new ArrayList();

        if (identity == null) {
            return roles.iterator();
        }

        Document usersdoc = null;
        try {
            usersdoc = getUserPasswordFileAsXMLDocument();
        } catch (Exception e) {
            throw new SystemException("Error opening XML users file:" + getXmlUsersFilename(), e);
        }

        Element elmUser = null;
        try {
            elmUser = (Element) XPathAPI.selectSingleNode(usersdoc.getDocumentElement(),  "user[@username = \"" + identity.getUserId() + "\"]");
        } catch (TransformerException e) {
            throw new SystemException("XML feil", e);
        }

        if (elmUser == null) {
            return roles.iterator();
        }

        String userRoles = elmUser.getAttribute(ROLES_MEMBER_ATTRIBUTE);
        if (userRoles != null && userRoles.length() > 0) {
            StringTokenizer tokens = new StringTokenizer(userRoles, ",");
            while (tokens.hasMoreTokens()) {
                String id = tokens.nextToken();
                DefaultRole role = new DefaultRole();
                role.setDomain(domain);
                role.setId(id);
                role.setName(id);
                roles.add(role);
            }
        }

        return roles.iterator();
    }


    public boolean userHasRole(Identity identity, String roleId) throws SystemException {
        Iterator allRoles = getRolesForUser(identity);
        while (allRoles.hasNext()) {
            Role role = (Role)allRoles.next();
            if (role.getId().equalsIgnoreCase(roleId)) {
                return true;
            }
        }

        return false;
    }
}
