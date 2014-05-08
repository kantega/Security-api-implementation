package no.kantega.security.api.impl.dbuser.password;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * A password hash with all metadata neccesary to recreate the hash form a plain text password
 *
 * User: Sigurd Stendal
 * Date: 07.05.14
 */
public class PasswordHash {

    private String hash;

    private List<Map<String, Object>> algorithms = new LinkedList<>();

    public PasswordHash() {
    }

    public void addAlgorithm(Map<String, Object> algorithm) {
        this.algorithms.add(algorithm);
    }

    public List<Map<String, Object>> getAlgorithms() {
        return algorithms;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }
}
