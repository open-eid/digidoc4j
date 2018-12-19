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
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class X509CertTest {

  private final X509Cert certificate = new X509Cert("src/test/resources/testFiles/certs/signout.pem");
  private final SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy");

  @Test
  public void testGetX509Certificate() throws Exception {
    X509Certificate x509Certificate = this.certificate.getX509Certificate();
    Assert.assertEquals("SERIALNUMBER=11404176865, GIVENNAME=MÄRÜ-LÖÖZ, SURNAME=ŽÕRINÜWŠKY, " +
            "CN=\"ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ,11404176865\", OU=digital signature, O=ESTEID, C=EE",
        x509Certificate.getSubjectDN().getName());
  }

  @Test
  public void testGetSerialNumber() {
    Assert.assertEquals("530be41bbc597c44570e2b7c13bcfa0c", this.certificate.getSerial());
  }

  @Test
  public void testGetIssuerName() {
    Assert.assertEquals("cn=test of esteid-sk 2015, oid.2.5.4.97=ntree-10747013, o=as sertifitseerimiskeskus, c=ee",
        this.certificate.issuerName().toLowerCase());
  }

  @Test
  public void testGetIssuerNameByPart() {
    Assert.assertNull(this.certificate.issuerName(X509Cert.Issuer.EMAILADDRESS));
    Assert.assertEquals("as sertifitseerimiskeskus", this.certificate.issuerName(X509Cert.Issuer.O).toLowerCase());
    Assert.assertEquals("test of esteid-sk 2015", this.certificate.issuerName(X509Cert.Issuer.CN).toLowerCase());
    Assert.assertEquals("ee", this.certificate.issuerName(X509Cert.Issuer.C).toLowerCase());
  }

  @Test
  public void testGetPolicies() throws IOException {
    Assert.assertEquals(1, this.certificate.getCertificatePolicies().size());
  }

  @Test
  public void testIsValidAtSpecifiedDate() {
    Assert.assertTrue(this.certificate.isValid(new Date()));
  }

  @Test
  public void testIsNotValidYet() throws ParseException {
    Date certValidFrom = this.dateFormat.parse("17.04.2014");
    Assert.assertFalse(this.certificate.isValid(new Date(certValidFrom.getTime() - TestConstants.ONE_DAY_IN_MILLIS)));
  }

  @Test
  public void testIsNoLongerValid() throws ParseException {
    Date certValidFrom = this.dateFormat.parse("12.04.2016");
    Assert.assertFalse(this.certificate.isValid(new Date(certValidFrom.getTime() + TestConstants.ONE_DAY_IN_MILLIS)));
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
    Assert.assertTrue(this.certificate.isValid());
  }

  @Test
  public void testKeyUsage() {
    Assert.assertEquals(Arrays.asList(X509Cert.KeyUsage.NON_REPUDIATION), this.certificate.getKeyUsages());
  }

  @Test
  public void testGetPartOfSubjectName() throws Exception {
    Assert.assertEquals("11404176865", this.certificate.getSubjectName(X509Cert.SubjectName.SERIALNUMBER));
    Assert.assertEquals("märü-lööz", this.certificate.getSubjectName(X509Cert.SubjectName.GIVENNAME).toLowerCase());
    Assert.assertEquals("žõrinüwšky", this.certificate.getSubjectName(X509Cert.SubjectName.SURNAME).toLowerCase());
    Assert.assertEquals("\"žõrinüwšky,märü-lööz,11404176865\"", this.certificate.getSubjectName(X509Cert.SubjectName.CN).toLowerCase());
    Assert.assertEquals("digital signature", this.certificate.getSubjectName(X509Cert.SubjectName.OU).toLowerCase());
    Assert.assertEquals("esteid", this.certificate.getSubjectName(X509Cert.SubjectName.O).toLowerCase());
    Assert.assertEquals("ee", this.certificate.getSubjectName(X509Cert.SubjectName.C).toLowerCase());
  }

  @Test
  public void testGetSubjectName() throws Exception {
    Assert.assertEquals("SERIALNUMBER=11404176865, GIVENNAME=MÄRÜ-LÖÖZ, SURNAME=ŽÕRINÜWŠKY, CN=\"ŽÕRINÜWŠKY,MÄRÜ-LÖÖZ," +
        "11404176865\", OU=digital signature, O=ESTEID, C=EE", this.certificate.getSubjectName());
  }

  @Test
  public void testDateCompare() throws Exception {
    Date startTime = Calendar.getInstance().getTime();
    Date usageTime = Calendar.getInstance().getTime();
    Assert.assertTrue(usageTime.compareTo(startTime) >= 0);
  }

}
