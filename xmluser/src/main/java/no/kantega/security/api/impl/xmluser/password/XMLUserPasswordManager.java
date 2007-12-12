package no.kantega.security.api.impl.xmluser.password;

import no.kantega.security.api.password.PasswordManager;
import no.kantega.security.api.identity.Identity;
import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.impl.xmluser.XMLUserManagerConfigurable;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.apache.xpath.XPathAPI;
import org.apache.log4j.Logger;

import javax.xml.transform.TransformerException;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jun 4, 2007
 * Time: 3:21:18 PM
 */
public class XMLUserPasswordManager extends XMLUserManagerConfigurable implements PasswordManager {

    private Logger log = Logger.getLogger(getClass());

    public boolean verifyPassword(Identity identity, String password) throws SystemException {
        if (!identity.getDomain().equalsIgnoreCase(domain)) {
            return false;
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
            return false;
        }

        String userPassword = elmUser.getAttribute("password");

        boolean correctPassword = userPassword.equalsIgnoreCase(password);
        if (correctPassword) {
            log.debug("Password verified for userid:" + identity.getUserId());
        } else {
            log.debug("Password verification failed for userid:" + identity.getUserId());
        }

        return correctPassword;
    }

    public void setPassword(Identity identity, String string, String string1) throws SystemException {

    }

    public boolean supportsPasswordChange() {
        return false;
    }

}
