package org.digidoc4j;

import java.security.cert.CertificateEncodingException;

import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.utils.PKCS12Signer;
import org.junit.Before;
import org.junit.Test;

import static java.util.Arrays.asList;
import static org.digidoc4j.utils.DateUtils.isAlmostNow;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SignatureTest {
  private Signer signer;

  @Before
  public void setUp() {
    signer = new PKCS12Signer("signout.p12", "test");
  }

  @Test
  public void testGetCity() {
    signer.setSignatureProductionPlace("myCity", "myState", "myPostalCode", "myCountry");
    Signature signature = new Signature(null, signer);
    assertEquals("myCity", signature.getCity());
    assertEquals("myCountry", signature.getCountryName());
    assertEquals("myPostalCode", signature.getPostalCode());
    assertEquals("myState", signature.getStateOrProvince());
  }

  @Test
  public void testGetSignerRoles() {
    signer.setSignerRoles(asList("Role / Resolution"));
    Signature signature = new Signature(null, signer);
    assertEquals(1, signature.getSignerRoles().size());
    assertEquals("Role / Resolution", signature.getSignerRoles().get(0));
  }

  @Test
  public void testGetMultipleSignerRoles() {
    signer.setSignerRoles(asList("Role 1", "Role 2"));
    Signature signature = new Signature(null, signer);
    assertEquals(2, signature.getSignerRoles().size());
    assertEquals("Role 1", signature.getSignerRoles().get(0));
    assertEquals("Role 2", signature.getSignerRoles().get(1));
  }

  @Test
  public void testSigningProperties() throws Exception {
    Container bDocContainer = new Container();
    bDocContainer.addDataFile("test.txt", "text/plain");
    PKCS12Signer signer = new PKCS12Signer("signout.p12", "test");
    signer.setSignatureProductionPlace("city", "stateOrProvince", "postalCode", "country");
    signer.setSignerRoles(asList("signerRoles"));
    Signature signature = bDocContainer.sign(signer);

    assertTrue(isAlmostNow(signature.getSigningTime()));
  }

  @Test
  public void testGetId() {
    Signature signature = getSignature();
    assertEquals("S0", signature.getId());
  }

  @Test
  public void testGetNonce() {
    Signature signature = getSignature();
    assertEquals(null, Base64.encodeBase64String(signature.getNonce())); //todo correct nonce is needed
  }

  @Test
  public void testGetOCSPCertificate() throws CertificateEncodingException {
    Signature signature = getSignature();
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
  public void testGetSignaturePolicy() {
    assertEquals("", getSignature().getPolicy());
  }

  @Test
  public void testGetProducedAt() {
    assertTrue(isAlmostNow(getSignature().getProducedAt()));
  }

  @Test
  public void testValidation() {
    assertEquals(0, getSignature().validate(SignatureInterface.Validate.VALIDATE_FULL).size());
  }

  @Test
  public void testValidationWithInvalidDocument() {
    Container container = new Container("changed_digdoc_test.ddoc");
    assertEquals(0, container.getSignatures().get(0).validate(SignatureInterface.Validate.VALIDATE_FULL).size());
  }

  private Signature getSignature() {
    Container container = new Container(ContainerInterface.DocumentType.DDOC);
    container.addDataFile("test.txt", "plain/text");
    return container.sign(new PKCS12Signer("signout.p12", "test"));
  }
}
