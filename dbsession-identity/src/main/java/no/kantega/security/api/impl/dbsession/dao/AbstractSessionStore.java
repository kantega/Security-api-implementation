package no.kantega.security.api.impl.dbsession.dao;

import java.math.BigInteger;
import java.security.SecureRandom;


public abstract class AbstractSessionStore implements SessionStore {
    private SecureRandom random = new SecureRandom();

    protected String generateKey() {
        BigInteger integer = new BigInteger(128, random);
        return integer.toString(16);
    }
}
