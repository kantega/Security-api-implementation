package no.kantega.security.api.impl.dbuser.password;

import java.security.NoSuchAlgorithmException;

/**
 * Author: Kristian Lier Selnæs, Kantega AS
 * Date: 27.mai.2008
 * Time: 13:30:08
 */
public interface PasswordCrypt {

    public String crypt(String password) throws NoSuchAlgorithmException;

    public String crypt(String password, String salt) throws NoSuchAlgorithmException;

}
