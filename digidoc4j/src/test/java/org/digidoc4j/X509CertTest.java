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

import java.io.IOException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import org.digidoc4j.test.TestConstants;
import org.junit.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class X509CertTest {

  private final X509Cert certificate = new X509Cert("src/test/resources/testFiles/certs/sign_RSA_from_TEST_of_ESTEIDSK2015.pem");
  private final SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy");

  @Test
  public void testGetX509Certificate() throws Exception {
    X509Certificate x509Certificate = this.certificate.getX509Certificate();
    assertEquals("SERIALNUMBER=60001013739, GIVENNAME=MARY ÄNN, SURNAME=O’CONNEŽ-ŠUSLIK TESTNUMBER, " +
            "CN=\"O’CONNEŽ-ŠUSLIK TESTNUMBER,MARY ÄNN,60001013739\", C=EE",
        x509Certificate.getSubjectDN().getName());
  }

  @Test
  public void testGetSerialNumber() {
    assertEquals("6ec00b8b8c54c4f76082bd843e3a1526", this.certificate.getSerial());
  }

  @Test
  public void testGetIssuerName() {
    assertEquals("cn=test of esteid-sk 2015, oid.2.5.4.97=ntree-10747013, o=as sertifitseerimiskeskus, c=ee",
        this.certificate.issuerName().toLowerCase());
  }

  @Test
  public void testGetIssuerNameByPart() {
    assertNull(this.certificate.issuerName(X509Cert.Issuer.EMAILADDRESS));
    assertEquals("as sertifitseerimiskeskus", this.certificate.issuerName(X509Cert.Issuer.O).toLowerCase());
    assertEquals("test of esteid-sk 2015", this.certificate.issuerName(X509Cert.Issuer.CN).toLowerCase());
    assertEquals("ee", this.certificate.issuerName(X509Cert.Issuer.C).toLowerCase());
  }

  @Test
  public void testGetPolicies() throws IOException {
    assertEquals(2, this.certificate.getCertificatePolicies().size());
  }

  @Test
  public void testIsValidAtSpecifiedDate() {
    assertTrue(this.certificate.isValid(new Date()));
  }

  @Test
  public void testIsNotValidYet() throws ParseException {
    Date certValidFrom = this.dateFormat.parse("17.04.2014");
    assertFalse(this.certificate.isValid(new Date(certValidFrom.getTime() - TestConstants.ONE_DAY_IN_MILLIS)));
  }

  @Test
  public void testIsNoLongerValid() throws ParseException {
    Date certValidFrom = this.dateFormat.parse("12.04.2016");
    assertFalse(this.certificate.isValid(new Date(certValidFrom.getTime() + TestConstants.ONE_DAY_IN_MILLIS)));
  }

  @Test
  public void testIsValidThrowsCertificateExpiredException() throws Exception {
    X509Certificate mock = Mockito.mock(X509Certificate.class);
    Mockito.doThrow(new CertificateExpiredException()).when(mock).checkValidity();
    new X509Cert(mock).isValid();
  }

  @Test
  public void testIsValidThrowsCertificateNotYetValidException() throws Exception {
    X509Certificate mock = Mockito.mock(X509Certificate.class);
    Mockito.doThrow(new CertificateNotYetValidException()).when(mock).checkValidity();
    new X509Cert(mock).isValid();
  }

  @Test
  public void testIsCertValidToday() {
    assertTrue(this.certificate.isValid());
  }

  @Test
  public void testKeyUsage() {
    assertEquals(Arrays.asList(X509Cert.KeyUsage.NON_REPUDIATION), this.certificate.getKeyUsages());
  }

  @Test
  public void testGetPartOfSubjectName() throws Exception {
    assertEquals("60001013739", this.certificate.getSubjectName(X509Cert.SubjectName.SERIALNUMBER));
    assertEquals("mary änn", this.certificate.getSubjectName(X509Cert.SubjectName.GIVENNAME).toLowerCase());
    assertEquals("o’connež-šuslik testnumber", this.certificate.getSubjectName(X509Cert.SubjectName.SURNAME).toLowerCase());
    assertEquals("\"o’connež-šuslik testnumber,mary änn,60001013739\"", this.certificate.getSubjectName(X509Cert.SubjectName.CN).toLowerCase());
    assertEquals("ee", this.certificate.getSubjectName(X509Cert.SubjectName.C).toLowerCase());
    assertNull(this.certificate.getSubjectName(X509Cert.SubjectName.OU));
    assertNull(this.certificate.getSubjectName(X509Cert.SubjectName.O));
  }

  @Test
  public void testGetSubjectName() throws Exception {
    assertEquals("SERIALNUMBER=60001013739, GIVENNAME=MARY ÄNN, SURNAME=O’CONNEŽ-ŠUSLIK TESTNUMBER, " +
        "CN=\"O’CONNEŽ-ŠUSLIK TESTNUMBER,MARY ÄNN,60001013739\", C=EE", this.certificate.getSubjectName());
  }

  @Test
  public void testDateCompare() throws Exception {
    Date startTime = Calendar.getInstance().getTime();
    Date usageTime = Calendar.getInstance().getTime();
    assertTrue(usageTime.compareTo(startTime) >= 0);
  }

}
