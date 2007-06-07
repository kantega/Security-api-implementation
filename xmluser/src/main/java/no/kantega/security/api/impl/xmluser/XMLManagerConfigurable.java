package no.kantega.security.api.impl.xmluser;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jun 4, 2007
 * Time: 4:00:34 PM
 */
public abstract class XMLManagerConfigurable {
    protected String xmlUsersFilename;
    protected String domain;

    public void setXmlUsersFilename(String xmlUsersFile) {
        this.xmlUsersFilename = xmlUsersFile;
    }

    public String getXmlUsersFilename() {
        return xmlUsersFilename;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    protected Document getUserPasswordFileAsXMLDocument() throws ParserConfigurationException, IOException, SAXException {
        File file = new File(xmlUsersFilename);
        Document doc = null;
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = docFactory.newDocumentBuilder();

        doc = builder.parse(file);

        return doc;
    }
}
