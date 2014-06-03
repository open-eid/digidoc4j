package ee.sk.digidoc4j;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import static java.util.Arrays.asList;
import static org.junit.Assert.*;

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

  @Test
  public void testIsValidAtSpecifiedDate() {
    assertTrue(cert.isValid(new Date()));
  }

  @Test
  public void testIsNotValidYet() throws ParseException {
    Date certValidFrom = new SimpleDateFormat("yyyy-MMMM-dd", Locale.ENGLISH).parse("2014-Apr-17");
    int OneDayInMilliSec = 1000 * 60 * 60 * 24;
    assertFalse(cert.isValid(new Date(certValidFrom.getTime() - OneDayInMilliSec)));
  }

  @Test
  public void testIsNoLongerValid() throws ParseException {
    Date certValidFrom = new SimpleDateFormat("yyyy-MMMM-dd", Locale.ENGLISH).parse("2016-Apr-12");
    int OneDayInMilliSec = 1000 * 60 * 60 * 24;
    assertFalse(cert.isValid(new Date(certValidFrom.getTime() + OneDayInMilliSec)));
  }

  @Test
  public void testIsCurrentlyValid() {
    assertTrue(cert.isValid());
  }

  @Test
  public void testKeyUsage() {
    assertEquals(asList(X509Cert.KeyUsage.NON_REPUDIATION), cert.getKeyUsages());
  }

  @Test
  public void testGetPartOfSubjectName() throws Exception {
    assertEquals("11404176865", cert.getSubjectName(X509Cert.SubjectName.SERIALNUMBER));
    assertEquals("märü-lööz", cert.getSubjectName(X509Cert.SubjectName.GIVENNAME).toLowerCase());
    assertEquals("žõrinüwšky", cert.getSubjectName(X509Cert.SubjectName.SURNAME).toLowerCase());
    assertEquals("\"žõrinüwšky,märü-lööz,11404176865\"", cert.getSubjectName(X509Cert.SubjectName.CN).toLowerCase());
    assertEquals("digital signature", cert.getSubjectName(X509Cert.SubjectName.OU).toLowerCase());
    assertEquals("esteid", cert.getSubjectName(X509Cert.SubjectName.O).toLowerCase());
    assertEquals("ee", cert.getSubjectName(X509Cert.SubjectName.C).toLowerCase());
  }

  @Test
  public void testGetSubjectName() throws Exception {
    assertEquals("SERIALNUMBER=11404176865, GIVENNAME=MÄRÜ-LÖÖZ, SURNAME=ŽÕRINÜWŠKY, CN=\"ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865\", OU=digital signature, O=ESTEID, C=EE", cert.getSubjectName());
  }
}
