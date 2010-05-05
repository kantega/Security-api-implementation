package no.kantega.security.api.impl.xmluser.profile;

import no.kantega.security.api.profile.ProfileManager;
import no.kantega.security.api.profile.Profile;
import no.kantega.security.api.profile.DefaultProfile;
import no.kantega.security.api.profile.ProfileComparator;
import no.kantega.security.api.search.DefaultProfileSearchResult;
import no.kantega.security.api.search.SearchResult;
import no.kantega.security.api.search.DefaultSearchResult;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.identity.DefaultIdentity;
import no.kantega.security.api.impl.xmluser.XMLUserManagerConfigurable;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.apache.xpath.XPathAPI;

import javax.xml.transform.TransformerException;
import java.util.List;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Collections;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jun 4, 2007
 * Time: 4:16:34 PM
 */
public class XMLUserProfileManager extends XMLUserManagerConfigurable implements ProfileManager {
    private static final String EMAIL_ATTRIBUTE = "email";
    private static final String DEPARTMENT_ATTRIBUTE = "department";

    public SearchResult<Profile> searchProfiles(String name) throws SystemException {
        DefaultProfileSearchResult searchResult = new DefaultProfileSearchResult();

        List<Profile> users = new ArrayList<Profile>();

        if (name == null || name.length() < 3) {
            return searchResult;
        }

        name = name.toLowerCase();

        Document usersdoc = null;
        try {
            usersdoc = getUserPasswordFileAsXMLDocument();
        } catch (Exception e) {
            throw new SystemException("Error opening XML users file:" + getXmlUsersFilename(), e);
        }

        try {
            NodeList lstUsers = XPathAPI.selectNodeList(usersdoc.getDocumentElement(), "user");
            for (int i = 0; i < lstUsers.getLength(); i++) {
                Element elmUser = (Element)lstUsers.item(i);
                String username = elmUser.getAttribute(USERNAME_ATTRIBUTE);
                if (username != null && username.toLowerCase().indexOf(name) != -1) {

                    DefaultProfile profile = new DefaultProfile();
                    DefaultIdentity identity = new DefaultIdentity();
                    identity.setDomain(domain);
                    identity.setUserId(username);
                    profile.setIdentity(identity);
                    profile.setGivenName(elmUser.getAttribute(USERNAME_ATTRIBUTE));
                    profile.setEmail(elmUser.getAttribute(EMAIL_ATTRIBUTE));
                    profile.setDepartment(elmUser.getAttribute(DEPARTMENT_ATTRIBUTE));

                    users.add(profile);
                }
            }
        } catch (Exception e) {
            throw new SystemException("Error processing XML users file:" + getXmlUsersFilename(), e);
        }

        // Sorter lista basert på navn på bruker
        Collections.sort(users, new ProfileComparator());

        searchResult.setResults(users);

        return searchResult;
    }

    public Profile getProfileForUser(Identity identity) throws SystemException {
        if (!identity.getDomain().equalsIgnoreCase(domain)) {
            return null;
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
            return null;
        }

        DefaultProfile profile = new DefaultProfile();
        profile.setIdentity(identity);
        profile.setGivenName(elmUser.getAttribute(USERNAME_ATTRIBUTE));
        profile.setEmail(elmUser.getAttribute(EMAIL_ATTRIBUTE));
        profile.setDepartment(elmUser.getAttribute(DEPARTMENT_ATTRIBUTE));

        return profile;
    }

    public boolean userHasProfile(Identity identity) throws SystemException {
        Profile p = getProfileForUser(identity);
        return p != null;
    }

    public static void main(String[] args) {
        XMLUserProfileManager manager = new XMLUserProfileManager();
        manager.setDomain("mydomain");
        manager.setXmlUsersFilename("/usr/local/tomcat5.0/conf/tomcat-users.xml");

        DefaultIdentity identity = new DefaultIdentity();
        identity.setDomain("mydomain");
        identity.setUserId("admin");
        try {
            Profile profile = manager.getProfileForUser(identity);
            if (profile != null) {
                System.out.println("Givenname:" + profile.getGivenName());
            } else {
                System.out.println("Profile == null");
            }

        } catch (SystemException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
    }
}
