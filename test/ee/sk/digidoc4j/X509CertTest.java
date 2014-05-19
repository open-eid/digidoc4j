package ee.sk.digidoc4j;

import org.junit.Test;

import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;

public class X509CertTest {

  @Test
  public void testGetX509Certificate() throws Exception {
    X509Cert cert = new X509Cert("signout.pem");
    X509Certificate x509Certificate = cert.getX509Certificate();
    assertEquals("SERIALNUMBER=11404176865, GIVENNAME=MÄRÜ-LÖÖZ, SURNAME=ŽÕRINÜWŠKY, " +
        "CN=\"ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865\", OU=digital signature, O=ESTEID, C=EE",
        x509Certificate.getSubjectDN().getName());
  }
}
