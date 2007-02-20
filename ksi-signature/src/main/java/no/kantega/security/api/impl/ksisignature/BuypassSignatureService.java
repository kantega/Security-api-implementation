package no.kantega.security.api.impl.ksisignature;

public class BuypassSignatureService extends AbstractSignatureService {
    private String profileUrlPart = "/buypass-sign";

     public String getSignatureServiceId() {
        return "urn:ksi:names:SAML:2.0:ac:classes:Buypass";
    }

    public String getSignatureServiceName() {
        return "Buypass";
    }

    public String getProfileUrlPart() {
        return profileUrlPart;
    }

    public String getFileSuffix() {
        return "pk7";
    }

    public String getType() {
        return "application/x-pkcs7-signature";
    }

    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();
        if(config.getProfileBuypassUrlpart() != null) {
            profileUrlPart = config.getProfileBuypassUrlpart();
        }
    }
}
