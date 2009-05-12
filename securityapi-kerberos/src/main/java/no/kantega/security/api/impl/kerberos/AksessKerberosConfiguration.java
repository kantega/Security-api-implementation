package no.kantega.security.api.impl.kerberos;

import org.simplericity.serberuhs.KerberosSubjectConfiguration;
import org.simplericity.serberuhs.filter.KerberosFilterConfiguration;

import javax.servlet.FilterConfig;

import no.kantega.publishing.common.Aksess;
import static no.kantega.publishing.common.Aksess.*;
import no.kantega.commons.configuration.Configuration;
import no.kantega.commons.exception.ConfigurationException;

import java.io.File;

/**
 * Created by IntelliJ IDEA.
 * User: bjorsnos
 * Date: May 12, 2009
 * Time: 1:36:15 PM
 * To change this template use File | Settings | File Templates.
 */
public class AksessKerberosConfiguration implements KerberosFilterConfiguration {

    private static final String KEYTAB_FILE_PROP = "kerberos.keytabFile";
    private static final String PRINCIPAL_PROP = "kerberos.principal";
    private static final String PASSWORD_PROP = "kerberos.password";
    private static final String REALM_PROP = "kerberos.realm";
    private static final String KDC_PROP = "kerberos.kdc";
    private final Configuration configuration;
    private File keytabFile;
    private String principal;
    private String password;
    private String realm;
    private String kdc;


    public AksessKerberosConfiguration(FilterConfig filterrConfig) {
        try {
            configuration = getConfiguration();
            verifyConfigurationPresent(configuration);
            String keyTab = configuration.getString(KEYTAB_FILE_PROP);
            if(keyTab == null) {
                keyTab = getDefaultKeyTab();
            }
            keytabFile = new File(keyTab);
            if(!keytabFile.exists()) {
                throw new IllegalArgumentException(KEYTAB_FILE_PROP + " does not exist: " + keytabFile.getAbsolutePath());
            }
            principal = configuration.getString(PRINCIPAL_PROP);
            password = configuration.getString(PASSWORD_PROP);
            realm = configuration.getString(REALM_PROP);
            kdc = configuration.getString(KDC_PROP);

        } catch (ConfigurationException e) {
            throw new IllegalArgumentException("Exception reading configuration", e);
        }
    }

    private String getDefaultKeyTab() {
        try {
            return new File(new File(Configuration.getApplicationDirectory()), "security/kerberos.keytab").getAbsolutePath();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public File getKeytabFile() {
        return keytabFile;
    }

    public String getPrincipal() {
        return principal;
    }

    public String getPassword() {
        return password;
    }

    public String getRealm() {
        return realm;
    }

    public String getKdc() {
        return kdc;
    }

    private void verifyConfigurationPresent(Configuration config) throws ConfigurationException {

        String[] props = new String[]{PRINCIPAL_PROP, PASSWORD_PROP, REALM_PROP, KDC_PROP};

        for (String prop : props) {
            if (config.getString(prop) == null) {
                throw new IllegalArgumentException("Filter configuration parameter '" + prop + "' is required");
            }
        }
    }

    public String getFallbackLoginPath() {
        return "/Login.action";
    }
}
