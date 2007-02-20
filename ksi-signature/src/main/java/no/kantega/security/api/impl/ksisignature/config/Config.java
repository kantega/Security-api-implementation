package no.kantega.security.api.impl.ksisignature.config;

import java.util.Properties;

/**
 * User: stelin
 * Date: 14.nov.2006
 * Time: 12:31:58
 */
public class Config {

    // The properties from the file
    Properties properties = new Properties();


    public Config(Properties properties) {
        this.properties = properties;
    }

    public String getSignportalUrl() {
        return get("signportal.url");
    }

    public String getProfileBankIDUrlpart(){
        return get("signportal.profile.bankid.urlpart");
    }

    public String getProfileBuypassUrlpart(){
        return get("signportal.profile.buypass.urlpart");
    }

    public String getSignportalWebServiceEndpoint() {
        return get("signportal.webservice.endpoint");
    }

    public String getDefaultSignTarget() {
        return get("federationagent.sign.default.target");
    }

    private String get(String key) {
        return properties.getProperty(key);
    }
}
