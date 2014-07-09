package org.digidoc4j.api;

import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.Certificates;
import org.digidoc4j.ContainerInterface;
import org.digidoc4j.api.exceptions.CertificateNotFoundException;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.NotYetImplementedException;
import org.digidoc4j.utils.PKCS12Signer;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import static java.util.Arrays.asList;
import static org.digidoc4j.ContainerInterface.DocumentType.ASIC_S;
import static org.digidoc4j.ContainerInterface.DocumentType.DDOC;
import static org.digidoc4j.SignatureInterface.Validate.VALIDATE_FULL;
import static org.digidoc4j.utils.DateUtils.isAlmostNow;
import static org.junit.Assert.*;

public class SignatureTest {

  private PKCS12Signer PKCS12_SIGNER;

  @Before
  public void setUp() throws Exception {
    PKCS12_SIGNER = new PKCS12Signer("testFiles/signout.p12", "test");
  }

  @Test
  public void testSigningProductionPlaceForDDOC() {
    testSigningProductionPlace(new Container(DDOC));
  }

  @Test
  public void testSigningProductionPlaceForASiCS() {
    testSigningProductionPlace(new Container(ASIC_S));
  }

  private void testSigningProductionPlace(Container container) {
    container.addDataFile("testFiles/test.txt", "text/plain");
    PKCS12Signer signer = PKCS12_SIGNER;
    signer.setSignatureProductionPlace("city", "state", "postalCode", "country");
    Signature signature = container.sign(signer);

    assertEquals("country", signature.getCountryName());
    assertEquals("city", signature.getCity());
    assertEquals("state", signature.getStateOrProvince());
    assertEquals("postalCode", signature.getPostalCode());
  }

  @Test
  public void testGetSigningCertificateForASiCS() throws Exception {
    Container container = new Container("testFiles/asics_for_testing.asics");
    byte[] certificate = container.getSignatures().get(0).getSigningCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.SIGNING_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test
  public void testGetTimeStampTokenCertificateForASiCS() throws Exception {
    Signature signature = new Container("testFiles/asics_ocsp_cert_is_not_in_tsl_test.asics").getSignatures().get(0);
    byte[] certificate = signature.getTimeStampTokenCertificate().getX509Certificate().getEncoded();
    assertEquals(Certificates.TS_CERTIFICATE, Base64.encodeBase64String(certificate));
  }

  @Test(expected = CertificateNotFoundException.class)
  public void testGetTimeStampTokenCertificateForASiCSNoTimeStampExists() throws Exception {
    new Container("testFiles/asics_for_testing.asics").getSignatures().get(0).getTimeStampTokenCertificate();
  }

  @Test
  public void testGetSignerRolesForDDOC() {
    testGetSignerRoles(new Container(DDOC));
  }

  @Test
  public void testGetSignerRolesForASiCS() {
    testGetSignerRoles(new Container(ASIC_S));
  }

  @Test(expected = CertificateNotFoundException.class)
  public void testGetSignerRolesForASiCS_OCSP_Exception() {
    Container container = new Container("testFiles/asics_ocsp_cert_is_not_in_tsl_test.asics");
    List<Signature> signatures = container.getSignatures();
    signatures.get(0).getOCSPCertificate();
  }

  private void testGetSignerRoles(Container container) {
    container.addDataFile("testFiles/test.txt", "text/plain");
    PKCS12_SIGNER.setSignerRoles(asList("Role / Resolution"));
    Signature signature = container.sign(PKCS12_SIGNER);
    assertEquals(1, signature.getSignerRoles().size());
    assertEquals("Role / Resolution", signature.getSignerRoles().get(0));
  }

  @Test
  public void testGetRawSignatureForASiCS() {
    Container container = new Container("testFiles/asics_for_testing.asics");
    List<Signature> signatures = container.getSignatures();
    assertEquals("IXMGT0c/U69uEhWZIZvitPQGD29Tx3oKO+9PNijzyRiupcjKTxlH306mbFfIYfVXkiu5n8mA183bzBH/CA5wgbccXwIwykEfay" +
        "Cm2/fGUNm5As9zErnzBWQ4s0oZWIVIi6DFR/QT/rzAoRNJ+1sPZBPvJlPofCW64FgkyADVAUDeCCkV6eAIr2ip+kwduJDmZwxrW/EqU1TA0" +
        "w77lhhAIw4KYEV4yi96eAzDL2rjB8VMUlmLYMnmz1oPdkOGmuj3pbfHV1w4zxYU9uM7LFNN2EogPt4oiH17VSNSlip+HCFdUqvf7hpLFLl2" +
        "iqxgVAijzvw0sMa2p5+iwLUfqCR45w==", new String(signatures.get(0).getRawSignature()));
  }

  @Test(expected = DigiDoc4JException.class)
  public void testGetMultipleSignerRolesForDDOC() {
    testGetMultipleSignerRoles(new Container(DDOC));
  }

  @Test
  public void testGetMultipleSignerRolesForASiCS() {
    testGetMultipleSignerRoles(new Container(ASIC_S));
  }

  private void testGetMultipleSignerRoles(Container container) {
    container.addDataFile("testFiles/test.txt", "text/plain");
    PKCS12_SIGNER.setSignerRoles(asList("Role 1", "Role 2"));
    Signature signature = container.sign(PKCS12_SIGNER);
    assertEquals(2, signature.getSignerRoles().size());
    assertEquals("Role 1", signature.getSignerRoles().get(0));
    assertEquals("Role 2", signature.getSignerRoles().get(1));
  }

  @Test
  public void testSigningProperties() throws Exception {
    Container bDocContainer = new Container();
    bDocContainer.addDataFile("testFiles/test.txt", "text/plain");
    PKCS12_SIGNER.setSignatureProductionPlace("city", "stateOrProvince", "postalCode", "country");
    PKCS12_SIGNER.setSignerRoles(asList("signerRoles"));
    Signature signature = bDocContainer.sign(PKCS12_SIGNER);

    assertTrue(isAlmostNow(signature.getSigningTime()));
  }

  @Test
  public void testGetSigningTimeForDDOC() {
    testGetSigningTime(DDOC);
  }

  @Test
  public void testGetSigningTimeForASiCS() {
    testGetSigningTime(ASIC_S);
  }

  private void testGetSigningTime(ContainerInterface.DocumentType ddoc) {
    Signature signature = getSignature(ddoc);
    assertTrue(isAlmostNow(signature.getSigningTime()));
  }

  @Test
  public void testGetIdForDDOC() {
    Signature signature = getSignature(DDOC);
    assertEquals("S0", signature.getId());
  }

  @Test
  public void testGetIdForASiCS() {
    Container container = new Container("testFiles/asics_ocsp_cert_is_not_in_tsl_test.asics");
    assertEquals("id-99E491801522116744419D9357CEFCC5", container.getSignatures().get(0).getId());
  }

  @Test
  public void testGetNonce() {
    Signature signature = getSignature(DDOC);
    assertEquals(null, Base64.encodeBase64String(signature.getNonce())); //todo correct nonce is needed
  }

  @Test
  public void testGetOCSPCertificateForDDoc() throws CertificateEncodingException {
    testGetOCSPCertificate(getSignature(DDOC));
  }

  @Test
  public void testGetOCSPCertificateForASiCS() throws CertificateEncodingException {
    testGetOCSPCertificate(getSignature(ASIC_S));
  }

  private void testGetOCSPCertificate(Signature signature) throws CertificateEncodingException {
    byte[] encoded = signature.getOCSPCertificate().getX509Certificate().getEncoded();
    assertEquals("MIIEijCCA3KgAwIBAgIQaI8x6BnacYdNdNwlYnn/mzANBgkqhkiG9w0BAQUFADB9" +
        "MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1" +
        "czEwMC4GA1UEAwwnVEVTVCBvZiBFRSBDZXJ0aWZpY2F0aW9uIENlbnRyZSBSb290" +
        "IENBMRgwFgYJKoZIhvcNAQkBFglwa2lAc2suZWUwHhcNMTEwMzA3MTMyMjQ1WhcN" +
        "MjQwOTA3MTIyMjQ1WjCBgzELMAkGA1UEBhMCRUUxIjAgBgNVBAoMGUFTIFNlcnRp" +
        "Zml0c2VlcmltaXNrZXNrdXMxDTALBgNVBAsMBE9DU1AxJzAlBgNVBAMMHlRFU1Qg" +
        "b2YgU0sgT0NTUCBSRVNQT05ERVIgMjAxMTEYMBYGCSqGSIb3DQEJARYJcGtpQHNr" +
        "LmVlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0cw6Cja17BbYbHi6" +
        "frwccDI4BIQLk/fiCE8L45os0xhPgEGR+EHE8LPCIqofPgf4gwN1vDE6cQNUlK0O" +
        "d+Ush39i9Z45esnfpGq+2HsDJaFmFr5+uC1MEz5Kn1TazEvKbRjkGnSQ9BertlGe" +
        "r2BlU/kqOk5qA5RtJfhT0psc1ixKdPipv59wnf+nHx1+T+fPWndXVZLoDg4t3w8l" +
        "IvIE/KhOSMlErvBIHIAKV7yH1hOxyeGLghqzMiAn3UeTEOgoOS9URv0C/T5C3mH+" +
        "Y/uakMSxjNuz41PneimCzbEJZJRiEaMIj8qPAubcbL8GtY03MWmfNtX6/wh6u6TM" +
        "fW8S2wIDAQABo4H+MIH7MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMJMB0GA1UdDgQW" +
        "BBR9/5CuRokEgGiqSzYuZGYAogl8TzCBoAYDVR0gBIGYMIGVMIGSBgorBgEEAc4f" +
        "AwEBMIGDMFgGCCsGAQUFBwICMEweSgBBAGkAbgB1AGwAdAAgAHQAZQBzAHQAaQBt" +
        "AGkAcwBlAGsAcwAuACAATwBuAGwAeQAgAGYAbwByACAAdABlAHMAdABpAG4AZwAu" +
        "MCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LnNrLmVlL2FqYXRlbXBlbC8wHwYDVR0j" +
        "BBgwFoAUtTQKnaUvEMXnIQ6+xLFlRxsDdv4wDQYJKoZIhvcNAQEFBQADggEBAAba" +
        "j7kTruTAPHqToye9ZtBdaJ3FZjiKug9/5RjsMwDpOeqFDqCorLd+DBI4tgdu0g4l" +
        "haI3aVnKdRBkGV18kqp84uU97JRFWQEf6H8hpJ9k/LzAACkP3tD+0ym+md532mV+" +
        "nRz1Jj+RPLAUk9xYMV7KPczZN1xnl2wZDJwBbQpcSVH1DjlZv3tFLHBLIYTS6qOK" +
        "4SxStcgRq7KdRczfW6mfXzTCRWM3G9nmDei5Q3+XTED41j8szRWglzYf6zOv4djk" +
        "ja64WYraQ5zb4x8Xh7qTCk6UupZ7je+0oRfuz0h/3zyRdjcRPkjloSpQp/NG8Rmr" +
        "cnr874p8d9fdwCrRI7U=", Base64.encodeBase64String(encoded));

  }

  @Test
  public void testGetSignaturePolicyForDDoc() {
    assertEquals("", getSignature(DDOC).getPolicy());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetSignaturePolicyForASiCS() throws Exception {
    Signature signature = getSignature(ASIC_S);
    assertEquals("", signature.getPolicy());
  }

  @Test
  public void testGetProducedAtForDDoc() {
    assertTrue(isAlmostNow(getSignature(DDOC).getProducedAt()));
  }

  @Test
  public void testGetProducedAtForASiCS() throws ParseException {
    Container container = new Container("testFiles/asics_ocsp_cert_is_not_in_tsl_test.asics");
    Date date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z").parse("2014-07-08 12:51:16 +0000");
    assertEquals(date, container.getSignatures().get(0).getProducedAt());
  }

  @Test
  public void testValidation() {
    assertEquals(0, getSignature(DDOC).validate(VALIDATE_FULL).size());
  }

  @Test
  public void testValidationNoParameters() {
    assertEquals(0, getSignature(DDOC).validate().size());
  }

  @Test
  public void testValidationWithInvalidDocument() {
    Container container = new Container("testFiles/changed_digidoc_test.ddoc");
    assertEquals(6, container.getSignatures().get(0).validate(VALIDATE_FULL).size());
  }

  @Test
  public void testGetSignaturePolicyURIForDDoc() {
    assertNull(getSignature(DDOC).getSignaturePolicyURI());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetSignaturePolicyURIForASiCS() throws Exception {
    Container container = new Container("testFiles/asics_ocsp_cert_is_not_in_tsl_test.asics");
    assertEquals(new URI(""), container.getSignatures().get(0).getSignaturePolicyURI());
  }

  @Test
  public void testGetSignatureMethodDDoc() {
    assertEquals("http://www.w3.org/2000/09/xmldsig#rsa-sha1", getSignature(DDOC).getSignatureMethod());
  }

  @Test
  public void testGetSignatureMethodForASiCS() {
    Container container = new Container("testFiles/asics_ocsp_cert_is_not_in_tsl_test.asics");
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256",
        container.getSignatures().get(0).getSignatureMethod());
  }

  @Test
  public void testGetProfileForDDoc() {
    assertEquals(ContainerInterface.SignatureProfile.TM, getSignature(DDOC).getProfile());
  }

  @Test
  public void testGetProfileForASiCS_TS() throws Exception {
    Container container = new Container("testFiles/asics_ocsp_cert_is_not_in_tsl_test.asics");
    assertEquals(ContainerInterface.SignatureProfile.TS, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void testGetProfileForASiCS_None() throws Exception {
    Container container = new Container("testFiles/asics_for_testing.asics");
    assertEquals(ContainerInterface.SignatureProfile.NONE, container.getSignatures().get(0).getProfile());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetTimeStampTokenCertificateForDDoc() {
    assertNull(getSignature(DDOC).getTimeStampTokenCertificate());
  }

  private Signature getSignature(ContainerInterface.DocumentType documentType) {
    Container container = new Container(documentType);
    container.addDataFile("testFiles/test.txt", "text/plain");

    return container.sign(PKCS12_SIGNER);
  }

  @Test(expected = NotYetImplementedException.class)
  public void testGetNonceForASiCS() {
    Container container = new Container("testFiles/asics_for_testing.asics");
    container.getSignatures().get(0).getNonce();
  }
}
