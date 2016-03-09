package no.kantega.security.api.impl.dbuser.password;

import java.util.LinkedList;
import java.util.List;

/**
 * A password hash with all metadata neccesary to recreate the hash form a plain text password
 */
public class PasswordHash {

    private String hash;

    private List<PasswordHashAlgorithm> algorithms = new LinkedList<>();

    public PasswordHash() {
    }

    public void addAlgorithm(PasswordHashAlgorithm algorithm) {
        this.algorithms.add(algorithm);
    }

    public List<PasswordHashAlgorithm> getAlgorithms() {
        return algorithms;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }
}
