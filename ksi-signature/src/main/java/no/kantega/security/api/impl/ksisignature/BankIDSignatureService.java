package no.kantega.security.api.impl.ksisignature;


public class BankIDSignatureService extends AbstractSignatureService {
     private String profileUrlPart = "/bankid-sign";
    
     public String getSignatureServiceId() {
        return "urn:ksi:names:SAML:2.0:ac:classes:BankID-NO";
    }

    public String getSignatureServiceName() {
        return "BankID";
    }

    public String getProfileUrlPart() {
        return profileUrlPart;
    }

    public String getFileSuffix() {
        return "sdo";
    }

    public String getType() {
        return "application/octet-stream";
    }

   public void afterPropertiesSet() throws Exception {
       super.afterPropertiesSet();
       if(config.getProfileBankIDUrlpart() != null) {
            profileUrlPart = config.getProfileBankIDUrlpart();
       }
    }
}
