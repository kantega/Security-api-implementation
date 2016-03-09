package no.kantega.security.api.impl.dbuser.password;

import java.util.HashMap;

public class PasswordHashAlgorithm extends HashMap<String, Object> {

    public String getId() {
        return (String) super.get("id");
    }

    public void setId(String id) {
        super.put("id", id);
    }

}
