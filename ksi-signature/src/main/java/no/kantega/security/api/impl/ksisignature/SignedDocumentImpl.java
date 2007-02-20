package no.kantega.security.api.impl.ksisignature;

import no.kantega.security.api.signature.SignedDocument;

/**
 * User: stelin
 * Date: 10.nov.2006
 * Time: 09:46:36
 */
public class SignedDocumentImpl implements SignedDocument {
    private byte[] content;
    private String type;
    private String fileSuffix;

    public byte[] getContent() {
        return content;
    }

    public String getType() {
        return type;
    }

    public String getFileSuffix() {
        return fileSuffix;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setFileSuffix(String fileSuffix) {
        this.fileSuffix = fileSuffix;
    }
}
