package no.kantega.security.api.impl.dbuser.password;

/**
 * A PasswordHasher can create a password hash form a plain text password and neccesary metadata
 * <p/>
 * User: Sigurd Stendal
 * Date: 06.05.14
 */
public interface PasswordHasher {

    /**
     * Creates a password hash. Generates all metadata. Returns a package with the hash and metadata like salt etc.
     *
     * @param password Clear text password
     * @return Package with hash and metadata
     */
    PasswordHash hashPassword(String password);

    /**
     * Creates a password hash. Returns a package with the hash and metadata like salt etc.
     *
     * @param password  Clear text password
     * @param algorithm Algorithm metadata
     * @return Package with hash and metadata
     */
    PasswordHash hashPassword(String password, PasswordHashAlgorithm algorithm);

    /**
     * The algorithm supported by this hasher
     */
    String getAlgorithm();
}
