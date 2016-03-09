package no.kantega.security.api.impl.dbuser.password;


import com.fasterxml.jackson.databind.ObjectMapper;
import no.kantega.security.api.impl.dbuser.password.PasswordHash;

import java.io.IOException;

public class PasswordHashJsonEncoder {

    private static ObjectMapper objectMapper = new ObjectMapper();

    public static String encode(PasswordHash hash) {
        try {
            return objectMapper.writeValueAsString(hash);
        } catch (IOException e) {
            throw new RuntimeException("Failed to json encode password hash", e);
        }
    }

    public static PasswordHash decode(String hash) {
        try {
            return objectMapper.readValue(hash, PasswordHash.class);
        } catch (IOException e) {
            throw new RuntimeException("Failed to json decode password hash", e);
        }
    }


}
