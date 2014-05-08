package no.kantega.security.api.impl.dbuser.password;

import no.kantega.security.api.common.SystemException;
import no.kantega.security.api.identity.Identity;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.*;

/**
 * User: Sigurd Stendal
 * Date: 07.05.14
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration({"classpath:/passwordRehashTestContext.xml", "classpath:/no/kantega/security/provider/dbuser.xml"})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class PasswordRehashTest {

    @Autowired
    DbUserPasswordRehasher rehasher;

    @Autowired
    PasswordDao passwordDao;

    @Autowired
    DbUserPasswordManager pwdmgr;

    @Test
    public void can_rehash_nonjson_hash() {

        rehasher.rehashAll();

        String hash = passwordDao.getPasswordHash("my domain", "jason");
        PasswordHash hashData = PasswordHashJsonEncoder.decode(hash);
        assertEquals(2, hashData.getAlgorithms().size());

    }

    @Test
    public void can_rehash_nonjson_hash_and_validate() throws SystemException {

        rehasher.rehashAll();

        assertTrue(pwdmgr.verifyPassword(createIdentity("my domain", "jason"), "password"));
        assertFalse(pwdmgr.verifyPassword(createIdentity("my domain", "jason"), "faulty password"));

    }


    private Identity createIdentity(final String domain, final String userId) {
        return new Identity() {
            @Override
            public String getUserId() {
                return userId;
            }

            @Override
            public String getDomain() {
                return domain;
            }
        };
    }
}
