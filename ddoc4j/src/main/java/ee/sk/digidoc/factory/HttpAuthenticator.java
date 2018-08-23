package ee.sk.digidoc.factory;

import java.net.Authenticator;
import java.net.PasswordAuthentication;

/**
 * HTTP authenticator class for ocsp requests
 * @author Veiko Sinivee
 */
public class HttpAuthenticator extends Authenticator
{
    private String m_username, m_passwd;

    public HttpAuthenticator(String username, String passwd)
    {
        m_username = username;
        m_passwd = passwd;
    }

    public PasswordAuthentication getPasswordAuthentication () {
        return new PasswordAuthentication (m_username, m_passwd.toCharArray());
    }
}