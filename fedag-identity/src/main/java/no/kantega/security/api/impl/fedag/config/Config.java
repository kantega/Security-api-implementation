package no.kantega.security.api.impl.fedag.config;

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

    public String getFedAgUrl() {
        return get("federationagent.url");
    }

    public String getDefaultAuthenticationTarget() {
        return get("federationagent.authn.default.target");
    }

    public String getSignportalUrl() {
        return get("signportal.url");
    }

    public String getSignportalWebServiceEndpoint() {
        return get("signportal.webservice.endpoint");
    }

    public String getDefaultSignTarget() {
        return get("federationagent.sign.default.target");
    }

    public String getSessionTableName() {
        String tableName = get("federationagent.session.tablename");
        if (tableName==null || "".equals(tableName)){
            tableName = "fedag_session";
        }
        return tableName;
    }

    public String getFedAgpProfile() {
        return get("federationagent.profile");
    }

    public String getIdentityServiceUrl() {
        return get("federationagent.identityservice.url");
    }

    public String getDefaultLogoutTargetUrl() {
        return get("federationagent.logout.default.target");
    }


    private String get(String key) {
        return properties.getProperty(key);
    }

    public String getFedagLogoutUrl() {
        return get("federationagent.logout.url");
    }
}
