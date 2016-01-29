/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.signers;

import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.X509Cert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.cert.CertificateEncodingException;
import java.util.Arrays;

import static org.digidoc4j.DigestAlgorithm.SHA512;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class PKCS12SignatureTokenTest {
  private static PKCS12SignatureToken pkcs12Signer;

  @BeforeClass
  public static void setUp() {
    pkcs12Signer = new PKCS12SignatureToken("testFiles/signout.p12", "test".toCharArray());
  }

  @Test
  public void getCertificate() throws CertificateEncodingException {
    X509Cert x509Cert = new X509Cert(pkcs12Signer.getCertificate());
    assertEquals("MIIFEzCCA/ugAwIBAgIQSXxaK/qTYahTT77Z9I56EjANBgkqhkiG9w0BAQUFADBsMQswC" +
            "QYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEfMB0GA1UEAwwWVEV" +
            "TVCBvZiBFU1RFSUQtU0sgMjAxMTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlMB4XDTE0MDQxNzExN" +
            "DUyOVoXDTE2MDQxMjIwNTk1OVowgbQxCzAJBgNVBAYTAkVFMQ8wDQYDVQQKDAZFU1RFSUQxGjAYBgN" +
            "VBAsMEWRpZ2l0YWwgc2lnbmF0dXJlMTEwLwYDVQQDDCjFvcOVUklOw5xXxaBLWSxNw4RSw5wtTMOWw" +
            "5ZaLDExNDA0MTc2ODY1MRcwFQYDVQQEDA7FvcOVUklOw5xXxaBLWTEWMBQGA1UEKgwNTcOEUsOcLUz" +
            "DlsOWWjEUMBIGA1UEBRMLMTE0MDQxNzY4NjUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBA" +
            "QChn9qVaA+x3RkDBrD5ujwfnreK5/Nb+Nvo9Vg5OLMn3JKUoUhFX6A/q5lBUylK/CU/lNRTv/kicqn" +
            "u1aCyAiW0XVYk8jrOI1wRbHeyBMq/5gVm/vbbRtMi/XGLkgMZ5UDxY0QZfmu8wlRJ8164zRNocuUJL" +
            "LXWOB6vda2RRXC3Cix4TDvQwGmPrQQJ8dzDIJEkLS7NCLBTcndm7buQegRc043gKMjUmRhGZEzF4oJ" +
            "a4pMfXqeSa+PUtrNyNNNQaOwTH29R8aFfGU2xorVvxoUieNipyWMEz8BTUGwwIceapWi77loBV/VQf" +
            "StXnQNu/s6BC04ss43O6sK70MB1qlRZAgMBAAGjggFmMIIBYjAJBgNVHRMEAjAAMA4GA1UdDwEB/wQ" +
            "EAwIGQDCBmQYDVR0gBIGRMIGOMIGLBgorBgEEAc4fAwEBMH0wWAYIKwYBBQUHAgIwTB5KAEEAaQBuA" +
            "HUAbAB0ACAAdABlAHMAdABpAG0AaQBzAGUAawBzAC4AIABPAG4AbAB5ACAAZgBvAHIAIAB0AGUAcwB" +
            "0AGkAbgBnAC4wIQYIKwYBBQUHAgEWFWh0dHA6Ly93d3cuc2suZWUvY3BzLzAdBgNVHQ4EFgQUEjVsO" +
            "kaNOGG0GlcF4icqxL0u4YcwIgYIKwYBBQUHAQMEFjAUMAgGBgQAjkYBATAIBgYEAI5GAQQwHwYDVR0" +
            "jBBgwFoAUQbb+xbGxtFMTjPr6YtA0bW0iNAowRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL3d3dy5za" +
            "y5lZS9yZXBvc2l0b3J5L2NybHMvdGVzdF9lc3RlaWQyMDExLmNybDANBgkqhkiG9w0BAQUFAAOCAQE" +
            "AYTJLbScA3+Xh/s29Qoc0cLjXW3SVkFP/U71/CCIBQ0ygmCAXiQIp/7X7JonY4aDz5uTmq742zZgq5" +
            "FA3c3b4NtRzoiJXFUWQWZOPE6Ep4Y07Lpbn04sypRKbVEN9TZwDy3elVq84BcX/7oQYliTgj5EaUvp" +
            "e7MIvkK4DWwrk2ffx9GRW+qQzzjn+OLhFJbT/QWi81Q2CrX34GmYGrDTC/thqr5WoPELKRg6a0v3mv" +
            "OCVtfIxJx7NKK4B6PGhuTl83hGzTc+Wwbaxwjqzl/SUwCNd2R8GV8EkhYH8Kay3Ac7Qx3agrJJ6H8j" +
            "+h+nCKLjIdYImvnznKyR0N2CRc/zQ+g==",
        Base64.encodeBase64String(x509Cert.getX509Certificate().getEncoded()));
  }

  @Test
  public void sign() {                                //TODO know expected value
    byte[] expected = new byte[]{121, 39, -126, -87, -118, -7, -79, 13, -52, -109, -8, -77, -15, 77, 12, 3, -10, -56,
        74, 112, -21, 54, -75,
        28, -19, -104, 2, -77, 41, -32, -93, 64, -119, 54, -98, -50, -88, 24, -85, -48, 24, -93, -18, -86, -24, -127,
        87, -125, -94, -21, 77, 87, 95,
        95, 22, -64, -104, 90, -13, -29, 113, -25, -21, 40, -50, -24, -5, -111, -83, -98, 62, 46, 68, -127, -100,
        112, 45, 82, -2, 51, 90, 65, -72,
        18, -67, 9, 40, 122, -55, 59, -83, -17, -63, 11, 117, -97, 25, 116, -93, -49, 88, -127, 92, -123, 23, 12, 5,
        -16, -91, -96, -30, 51, -77, 116,
        -36, 97, -73, -20, -80, 98, -5, -123, 118, -19, 59, -84, -30, 52, -25, -82, -104, -118, -80, -91, -8, 100,
        -19, 105, 65, -83, -2, 73, -101,
        -54, 90, -20, 95, -78, 113, -95, 81, 42, 93, 10, -121, 12, 99, 31, 29, 61, -99, 60, -82, 100, -39, 86, -81,
        68, -42, 75, 100, 60, -80, 99, -31,
        109, 48, -80, -22, -7, 34, -110, 103, -114, 63, 30, -34, 92, 11, 51, -22, 75, 52, 9, -103, 108, -113, 11,
        -96, -73, -14, -122, -18, 105, 38,
        -85, 96, -23, -115, 107, -106, 57, 105, 27, -106, 75, -111, -41, 59, -23, 113, -55, 86, 70, 64, -118, -80,
        44, -48, -19, 99, -43, 106, -26,
        97, -119, -94, -9, -22, -8, 88, 62, 67, -80, 35, 110, -7, -10, 55, 73, -60, 83, -128, -57, -120, 2};
    assertTrue(Arrays.equals(expected, pkcs12Signer.sign(SHA512, new byte[]{0x41})));
  }

//  @Test
//  public void getCity() {
//    pkcs12Signer.setSignatureProductionPlace("myCity", "myState", "myPostalCode", "myCountry");
//    assertEquals("myCity", pkcs12Signer.getCity());
//  }
//
//  @Test
//  public void getCityWhenEmpty() {
//    pkcs12Signer.setSignatureProductionPlace("", "myState", "myPostalCode", "myCountry");
//    assertEquals("", pkcs12Signer.getCity());
//  }
//
//  @Test
//  public void getCityWhenNull() {
//    pkcs12Signer.setSignatureProductionPlace(null, "myState", "myPostalCode", "myCountry");
//    assertNull(pkcs12Signer.getCity());
//  }
//
//  @Test
//  public void getStateOrProvince() {
//    pkcs12Signer.setSignatureProductionPlace("myCity", "myState", "myPostalCode", "myCountry");
//    assertEquals("myState", pkcs12Signer.getStateOrProvince());
//  }
//
//  @Test
//  public void getStateOrProvinceWhenEmpty() {
//    pkcs12Signer.setSignatureProductionPlace("myCity", "", "myPostalCode", "myCountry");
//    assertEquals("", pkcs12Signer.getStateOrProvince());
//  }
//
//  @Test
//  public void getStateOrProvinceWhenNull() {
//    pkcs12Signer.setSignatureProductionPlace("myCity", null, "myPostalCode", "myCountry");
//    assertNull(pkcs12Signer.getStateOrProvince());
//  }
//
//  @Test
//  public void getPostalCode() {
//    pkcs12Signer.setSignatureProductionPlace("myCity", "myState", "myPostalCode", "myCountry");
//    assertEquals("myPostalCode", pkcs12Signer.getPostalCode());
//  }
//
//  @Test
//  public void getPostalCodeWhenEmpty() {
//    pkcs12Signer.setSignatureProductionPlace("myCity", "myState", "", "myCountry");
//    assertEquals("", pkcs12Signer.getPostalCode());
//  }
//
//  @Test
//  public void getPostalCodeWhenNull() {
//    pkcs12Signer.setSignatureProductionPlace("myCity", "myState", null, "myCountry");
//    assertNull(pkcs12Signer.getPostalCode());
//  }
//
//  @Test
//  public void getCountry() {
//    pkcs12Signer.setSignatureProductionPlace("myCity", "myState", "myPostalCode", "myCountry");
//    assertEquals("myCountry", pkcs12Signer.getCountry());
//  }
//
//  @Test
//  public void getCountryWhenEmpty() {
//    pkcs12Signer.setSignatureProductionPlace("myCity", "myState", "myPostalCode", "");
//    assertEquals("", pkcs12Signer.getCountry());
//  }
//
//  @Test
//  public void getCountryWhenNull() {
//    pkcs12Signer.setSignatureProductionPlace("myCity", "myState", "myPostalCode", null);
//    assertNull(pkcs12Signer.getCountry());
//  }
//
//  @Test
//  public void getSignerRoles() {
//    pkcs12Signer.setSignerRoles(asList("Role / Resolution"));
//    Assert.assertEquals(1, pkcs12Signer.getSignerRoles().size());
//    assertEquals("Role / Resolution", pkcs12Signer.getSignerRoles().get(0));
//  }
//
//  @Test
//  public void getMultipleSignerRoles() {
//    pkcs12Signer.setSignerRoles(asList("Role 1", "Role 2"));
//    Assert.assertEquals(2, pkcs12Signer.getSignerRoles().size());
//    assertEquals("Role 1", pkcs12Signer.getSignerRoles().get(0));
//    assertEquals("Role 2", pkcs12Signer.getSignerRoles().get(1));
//  }
//
//  @Test
//  public void addSignatureProductionPlace() throws Exception {
//    SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
//    signatureProductionPlace.setCountry("Country");
//    pkcs12Signer.setSignatureProductionPlace(signatureProductionPlace);
//
//    assertEquals("Country", pkcs12Signer.getCountry());
//    SignatureProductionPlace productionPlaceToTest = pkcs12Signer.getSignatureProductionPlace();
//    assertEquals("Country", productionPlaceToTest.getCountry());
//  }
}
