package no.kantega.security.api.impl.dbuser.password;

import java.util.HashMap;

/**
 * User: Sigurd Stendal
 * Date: 09.05.14
 */
public class PasswordHashAlgorithm extends HashMap<String, Object> {

    public String getId() {
        return (String) super.get("id");
    }

    public void setId(String id) {
        super.put("id", id);
    }

}
