package no.kantega.security.api.impl.signicat;

/**
 * Date: Apr 27, 2010
 * Time: 9:47:02 AM
 *
 * @author Tarje Killingberg
 */
public class SignicatConfiguration {

    
    /**
     * The URL to the login page, for instance <code>https://id.signicat.com/std/method/shared?method=nbid&amp;target=</code>.
     */
    private String loginUrl;

    /**
     * The attribute whose value should be treated as the User ID.
     */
    private String userIdAttribute;

    /**
     * Distinguished name in certificate from trusted signicat.com instance.
     */
    private String trustedCertificate;

    /**
     * Whether the Signicat client library should print debug messages.
     */
    private boolean debug;

    /**
     * A known difference between the system clock on the server and the client
     * in seconds. A positive value should be used if the system clock on your
     * server is earlier than the Signicat server system clock.
     */
    private int timeSkew;


    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public String getUserIdAttribute() {
        return userIdAttribute;
    }

    public void setUserIdAttribute(String userIdAttribute) {
        this.userIdAttribute = userIdAttribute;
    }

    public String getTrustedCertificate() {
        return trustedCertificate;
    }

    public void setTrustedCertificate(String trustedCertificate) {
        this.trustedCertificate = trustedCertificate;
    }

    public boolean isDebug() {
        return debug;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    public int getTimeSkew() {
        return timeSkew;
    }

    public void setTimeSkew(int timeSkew) {
        this.timeSkew = timeSkew;
    }

}
