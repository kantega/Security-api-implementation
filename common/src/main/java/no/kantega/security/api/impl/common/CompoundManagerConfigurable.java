package no.kantega.security.api.impl.common;

import java.util.List;

/**
 * User: Anders Skar, Kantega AS
 * Date: Jun 7, 2007
 * Time: 10:32:40 AM
 */
public abstract class CompoundManagerConfigurable {
    protected String domain;
    protected List managers;

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public void setManagers(List managers) {
        this.managers = managers;
    }
}
