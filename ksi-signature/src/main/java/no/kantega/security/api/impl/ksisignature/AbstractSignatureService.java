package no.kantega.security.api.impl.ksisignature;

import no.kantega.security.api.signature.*;
import no.kantega.security.api.impl.ksisignature.config.Config;
import org.apache.log4j.Logger;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.InitializingBean;

import javax.xml.rpc.ServiceException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLEncoder;

import ksi.client.signatureservice.SignatureEndpointServiceLocator;
import ksi.client.signatureservice.SignatureEndpoint;

/**
 * User: stelin
 * Date: 10.nov.2006
 * Time: 09:46:28
 */
public abstract class AbstractSignatureService implements SignatureService, InitializingBean {
    private Logger logger = Logger.getLogger(getClass());
    private String signportalUrl;
    private String signportalWebServiceEndpoint;
    private static final String TARGET_PARAMETER_NAME = "target";
    private static final String ARTIFACT_PARAMETER_NAME = "documentArtifact";
    protected Config config;
    private String defaultSignTargetUrl;

    public void setConfig(Config config) {
        this.config = config;
    }

    public final String preparePlainTextSignature(String string, SignatureContext signatureContext) throws SignatureException {
        return prepareSigning(signatureContext, string.getBytes(), "text/plain");
    }


    public final String preparePdfSignature(byte[] bytes, SignatureContext signatureContext) throws SignatureException {
        return prepareSigning(signatureContext, bytes, "application/pdf");
    }

    private String prepareSigning(SignatureContext signatureContext, byte[] documentBytes, String mimeType) throws SignatureException {

        // Base64 encode data
        byte[] base64encoded = Base64.encodeBase64(documentBytes);
        try {
            // locate web service
            SignatureEndpointServiceLocator locator = new SignatureEndpointServiceLocator();
            SignatureEndpoint service = locator.getsignatureservice(new URL(signportalWebServiceEndpoint));
            String documentDescription = signatureContext.getDescription();
            if (documentDescription==null || "".equals(documentDescription)){
                String msg = "signatureContext.description cannot be empty or null";
                logger.info(msg);
                throw new SignatureException(msg);
            }
            return service.registerDocument(new String(base64encoded), mimeType, documentDescription);
        } catch (IOException e) {
            String msg = "Error during redirect for signing";
            logger.error(msg, e);
            throw new SignatureException(msg, e);
        } catch (ServiceException e) {
            String msg = "Wrong url for redirect to signing";
            logger.error(msg, e);
            throw new SignatureException();
        }
    }

    public void dispatchSigning(String artifact, SignatureDispatchContext signatureDispatchContext) throws SignatureException {
        String targetUrl;
        if (signatureDispatchContext.getReturnUri() != null) {

            targetUrl = signatureDispatchContext.getReturnUri().toString();

        } else {
            logger.debug("Using default sign target from config.");
            targetUrl = defaultSignTargetUrl ;
        }


        //building sign url
        String url = signportalUrl +getProfileUrlPart();
        url += "?";
        try {
            url += TARGET_PARAMETER_NAME + "=" + URLEncoder.encode(targetUrl, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
        url += "&";
        url += ARTIFACT_PARAMETER_NAME + "=" + artifact;

        logger.info("Redirecting for signing: " + url);
        try {
            signatureDispatchContext.getResponse().sendRedirect(url);
        } catch (IOException e) {
            String msg = "Error during redirect for signing";
            logger.error(msg, e);
            throw new SignatureException(msg, e);
        }
    }

    public SignedDocument getSignedDocument(String artifact) throws SignatureException {
        try {
            SignatureEndpointServiceLocator locator = new SignatureEndpointServiceLocator();
            SignatureEndpoint service = locator.getsignatureservice(new URL(signportalWebServiceEndpoint));

            String signedDocumentBase64 = service.retrieveSignedDocument(artifact);
            byte[] bytes = Base64.decodeBase64(signedDocumentBase64.getBytes());

            SignedDocumentImpl signedDocument = new SignedDocumentImpl();

            signedDocument.setContent(bytes);
            signedDocument.setFileSuffix(getFileSuffix());
            signedDocument.setType(getType());
            logger.info("Returning signed document with artifact "+artifact+" and type "+getType());
            return signedDocument;

        } catch (Exception e) {
            String msg = "Error retrieving signed document using artifact: " + artifact;
            logger.error(msg, e);
            throw new SignatureException(msg, e);
        }
    }

    public abstract String getProfileUrlPart();

    public abstract String getFileSuffix();

    public abstract String getType();

    public void afterPropertiesSet() throws Exception {
        defaultSignTargetUrl = config.getDefaultSignTarget();
        signportalUrl = config.getSignportalUrl();
        signportalWebServiceEndpoint = config.getSignportalWebServiceEndpoint();
    }
}
