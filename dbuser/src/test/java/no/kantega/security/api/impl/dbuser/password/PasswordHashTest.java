package no.kantega.security.api.impl.dbuser.password;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * User: Sigurd Stendal
 * Date: 07.05.14
 */
public class PasswordHashTest {

    @Test
    public void can_json_encode_and_decode() {

        PasswordHash hash = new PasswordHash();
        hash.setHash("XYZ");
        PasswordHashAlgorithm algorithm = new PasswordHashAlgorithm();
        algorithm.setId("MYALG");
        algorithm.put("some-parameter", "some value");
        algorithm.put("other-parameter", 1);
        hash.addAlgorithm(algorithm);

        String encoded = PasswordHashJsonEncoder.encode(hash);

        System.out.println(encoded);

        hash = PasswordHashJsonEncoder.decode(encoded);

        assertEquals("XYZ", hash.getHash());
        assertEquals(1, hash.getAlgorithms().size());
        assertEquals("MYALG", hash.getAlgorithms().get(0).getId());
        assertEquals(1, hash.getAlgorithms().get(0).get("other-parameter"));
    }


    @Test
    public void can_create_and_validate_pbkdf2() {

        Pbkdf2WithHmacSha1PasswordHasher hasher = new Pbkdf2WithHmacSha1PasswordHasher();

        PasswordHash hashData = hasher.hashPassword("my secret");

        assertTrue(hashData.getHash().length() > 0);
        assertEquals(1, hashData.getAlgorithms().size());
        assertEquals("PBKDF2WithHmacSha1", hashData.getAlgorithms().get(0).getId());
        assertEquals(1000, hashData.getAlgorithms().get(0).get("iterations"));

        PasswordHash hashData2 = hasher.hashPassword("my secret", hashData.getAlgorithms().get(0));
        assertEquals(hashData2.getHash(), hashData.getHash());

    }

}