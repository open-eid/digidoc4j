/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import static java.util.Arrays.asList;
import static org.digidoc4j.X509Cert.SubjectName.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

public class X509CertTest {

  private static X509Cert cert;
  private final int ONE_DAY = 1000 * 60 * 60 * 24;
  private final SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy");

  @BeforeClass
  public static void setUp() throws Exception {
    cert = new X509Cert("testFiles/signout.pem");
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
    assertEquals("530be41bbc597c44570e2b7c13bcfa0c", cert.getSerial());
  }

  @Test
  public void testGetIssuerName() {
    assertEquals("cn=test of esteid-sk 2015, oid.2.5.4.97=ntree-10747013, o=as sertifitseerimiskeskus, c=ee",
        cert.issuerName().toLowerCase());
  }

  @Test
  public void testGetIssuerNameByPart() {
    assertNull(cert.issuerName(X509Cert.Issuer.EMAILADDRESS));
    assertEquals("as sertifitseerimiskeskus", cert.issuerName(X509Cert.Issuer.O).toLowerCase());
    assertEquals("test of esteid-sk 2015", cert.issuerName(X509Cert.Issuer.CN).toLowerCase());
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
    Date certValidFrom = dateFormat.parse("17.04.2014");
    assertFalse(cert.isValid(new Date(certValidFrom.getTime() - ONE_DAY)));
  }

  @Test
  public void testIsNoLongerValid() throws ParseException {
    Date certValidFrom = dateFormat.parse("12.04.2016");
    assertFalse(cert.isValid(new Date(certValidFrom.getTime() + ONE_DAY)));
  }

  @Test
  public void testIsValidThrowsCertificateExpiredException() throws Exception {
    X509Certificate mock = mock(X509Certificate.class);
    Mockito.doThrow(new CertificateExpiredException()).when(mock).checkValidity();
    X509Cert x509Cert = new X509Cert(mock);
    x509Cert.isValid();
  }

  @Test
  public void testIsValidThrowsCertificateNotYetValidException() throws Exception {
    X509Certificate mock = mock(X509Certificate.class);
    Mockito.doThrow(new CertificateNotYetValidException()).when(mock).checkValidity();
    X509Cert x509Cert = new X509Cert(mock);
    x509Cert.isValid();
  }

  @Test
  public void testIsCertValidToday() {
    assertTrue(cert.isValid());
  }

  @Test
  public void testKeyUsage() {
    assertEquals(asList(X509Cert.KeyUsage.NON_REPUDIATION), cert.getKeyUsages());
  }

  @Test
  public void testGetPartOfSubjectName() throws Exception {
    assertEquals("11404176865", cert.getSubjectName(SERIALNUMBER));
    assertEquals("märü-lööz", cert.getSubjectName(GIVENNAME).toLowerCase());
    assertEquals("žõrinüwšky", cert.getSubjectName(SURNAME).toLowerCase());
    assertEquals("\"žõrinüwšky,märü-lööz,11404176865\"", cert.getSubjectName(CN).toLowerCase());
    assertEquals("digital signature", cert.getSubjectName(OU).toLowerCase());
    assertEquals("esteid", cert.getSubjectName(O).toLowerCase());
    assertEquals("ee", cert.getSubjectName(C).toLowerCase());
  }

  @Test
  public void testGetSubjectName() throws Exception {
    assertEquals("SERIALNUMBER=11404176865, GIVENNAME=MÄRÜ-LÖÖZ, SURNAME=ŽÕRINÜWŠKY, CN=\"ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ," +
        "11404176865\", OU=digital signature, O=ESTEID, C=EE", cert.getSubjectName());
  }
}
