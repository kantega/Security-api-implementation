package no.kantega.security.api.impl.dbsession.dao;

public interface SessionStore {
    public String storeSession(String username);

    public Session getSession(String key);

    void removeSession(String keyParam);
}
