package ee.sk.digidoc4j;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;

public class X509CertTest {

  private static X509Cert cert;

  @BeforeClass
  public static void setUp() throws Exception {
    cert = new X509Cert("signout.pem");
  }

  @Test
  public void testGetX509Certificate() throws Exception {
    X509Certificate x509Certificate = cert.getX509Certificate();
    assertEquals("SERIALNUMBER=11404176865, GIVENNAME=MÄRÜ-LÖÖZ, SURNAME=ŽÕRINÜWŠKY, " +
        "CN=\"ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865\", OU=digital signature, O=ESTEID, C=EE",
        x509Certificate.getSubjectDN().getName());
  }

  @Test
  public void testGetSerialNumber() {
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12", cert.getSerial());
  }

  @Test
  public void testGetIssuerName() {
    assertEquals("emailaddress=pki@sk.ee, cn=test of esteid-sk 2011, o=as sertifitseerimiskeskus, c=ee",
        cert.issuerName().toLowerCase());
  }

  @Test
  public void testGetIssuerNameByPart() {
    assertEquals("pki@sk.ee", cert.issuerName(X509Cert.Issuer.EMAILADDRESS).toLowerCase());
    assertEquals("as sertifitseerimiskeskus", cert.issuerName(X509Cert.Issuer.O).toLowerCase());
    assertEquals("test of esteid-sk 2011", cert.issuerName(X509Cert.Issuer.CN).toLowerCase());
    assertEquals("ee", cert.issuerName(X509Cert.Issuer.C).toLowerCase());
  }

  @Test
  public void testGetPolicies() throws IOException {
    assertEquals(1, cert.getCertificatePolicies().size());
  }
}
