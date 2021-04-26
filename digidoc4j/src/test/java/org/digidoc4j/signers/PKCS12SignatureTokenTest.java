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
import org.digidoc4j.AbstractTest;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.InvalidKeyException;
import org.junit.Assert;
import org.junit.Test;

import java.security.cert.CertificateEncodingException;

public class PKCS12SignatureTokenTest extends AbstractTest {

  @Test
  public void getCertificate() throws CertificateEncodingException {
    X509Cert x509Cert = new X509Cert(pkcs12SignatureToken.getCertificate());
    Assert.assertEquals("MIIGuDCCBKCgAwIBAgIQbsALi4xUxPdggr2EPjoVJjANBgkqhkiG9w0BAQsFADBr" +
            "MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1" +
            "czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHzAdBgNVBAMMFlRFU1Qgb2YgRVNU" +
            "RUlELVNLIDIwMTUwIBcNMjEwNDIzMTIyODUyWhgPMjAzMDEyMTcyMzU5NTlaMIGf" +
            "MQswCQYDVQQGEwJFRTE9MDsGA1UEAww0T+KAmUNPTk5Fxb0txaBVU0xJSyBURVNU" +
            "TlVNQkVSLE1BUlkgw4ROTiw2MDAwMTAxMzczOTEnMCUGA1UEBAweT+KAmUNPTk5F" +
            "xb0txaBVU0xJSyBURVNUTlVNQkVSMRIwEAYDVQQqDAlNQVJZIMOETk4xFDASBgNV" +
            "BAUTCzYwMDAxMDEzNzM5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" +
            "r8Gtz4AS8HoY2UpUvD9/OxJzymnvSTR5LKcG7+rLdXszEgdyRCy0sHg1yRseZgXu" +
            "XQsAG/IGKQFUOBND6LAD2Puv+wk4HenB7EZmeiDQzdKGE3CoRz+UU+zz8EqQTzZi" +
            "l85R7kK1oDi3b1RtB4flELSQ38ufeOFAli97K2hhYGVtPDOcJIbz4jej4UqQnY80" +
            "Ma+5niQxsN9pf2W/Fe2r7TMtqmo+aKbaWMr3uLESbPGpiffetcWnllmLQR2lcx2w" +
            "aHXp3XeUQXHBbtO0oypaxpgDTcRBLH3ZGuElj0KGfXqRaO6dwOjjHG5G8+Tzvy/2" +
            "pvGuqbr9RvcH3QMmG1mEswIDAQABo4ICHzCCAhswCQYDVR0TBAIwADAOBgNVHQ8B" +
            "Af8EBAMCBkAwdQYDVR0gBG4wbDBfBgorBgEEAc4fAwEDMFEwHgYIKwYBBQUHAgIw" +
            "EgwQT25seSBmb3IgVEVTVElORzAvBggrBgEFBQcCARYjaHR0cHM6Ly93d3cuc2su" +
            "ZWUvcmVwb3NpdG9vcml1bS9DUFMwCQYHBACL7EABAjAdBgNVHQ4EFgQUNGA6HJQi" +
            "W4kukHbhN6CmD0Js1McwgYoGCCsGAQUFBwEDBH4wfDAIBgYEAI5GAQEwCAYGBACO" +
            "RgEEMFEGBgQAjkYBBTBHMEUWP2h0dHBzOi8vc2suZWUvZW4vcmVwb3NpdG9yeS9j" +
            "b25kaXRpb25zLWZvci11c2Utb2YtY2VydGlmaWNhdGVzLxMCRU4wEwYGBACORgEG" +
            "MAkGBwQAjkYBBgEwHwYDVR0jBBgwFoAUScDyRDll1ZtGOw04YIOx1i0ohqYwgYMG" +
            "CCsGAQUFBwEBBHcwdTAsBggrBgEFBQcwAYYgaHR0cDovL2FpYS5kZW1vLnNrLmVl" +
            "L2VzdGVpZDIwMTUwRQYIKwYBBQUHMAKGOWh0dHBzOi8vc2suZWUvdXBsb2FkL2Zp" +
            "bGVzL1RFU1Rfb2ZfRVNURUlELVNLXzIwMTUuZGVyLmNydDA0BgNVHR8ELTArMCmg" +
            "J6AlhiNodHRwczovL2Muc2suZWUvdGVzdF9lc3RlaWQyMDE1LmNybDANBgkqhkiG" +
            "9w0BAQsFAAOCAgEAn5yOThHC3o+qywote9HYZz6TgGUin606KONrUcbsP9UMZwKF" +
            "HhQBAZE9ycJ3iOIKtEk0VlH5vwL0MvyY26VyHgkprozEcX5OCQKBCTn/ZKR+IIXQ" +
            "wNT0ZadQHTAuCLidHH9bI4/CofTWtr6udYezmQs7FIXbcazQ6cgkb937HulVHt4x" +
            "IDZ8kp9oUaqbpUfCSu5zOspQRM2ih0MshPmZvkS9qeFgbkTD0D+RPccxV7jjHCbH" +
            "xjHzYNFrq2JJuKacxx/OR12KGKOtcGlYjFxWl18MJ/n3tvoEcWaXKtPZ+BmStbPH" +
            "RFb29fkSIWtEzFRSbbLYeHkC53m8lWQ4kXhMJ10aZs9nXRVJ0I4/wMjZTpO6lMkq" +
            "Exm77nyycxPv3glJWssFp5LEKgJKxWt2aT9ihHypqEPVjBZGfppFOJT81gxLLF0k" +
            "MVxnRqpNbi/1thY5IIxFgGzxIHJlIMuw/HECMJ+/n19dF+Z8tqCoxhNxEQm409jR" +
            "v6/RsRhtQ5IIY0PR8eL5xzwgET5BWy5AjUtzGeQsEiywY9+kNfLgv0GQsdfiyhyG" +
            "z5oX/8t9AlntTTLpUdWRs4IU3M1yLV2qxc/zAyXRZYJ5nbkwg1oR3wttTYcQ+uFk" +
            "0qCoYsLHPmNmFGYZrt00lbulpieIS/YGdFmdtQn7vip/y7LOGEU02m84Lpo=",
        Base64.encodeBase64String(x509Cert.getX509Certificate().getEncoded()));
  }

  @Test
  public void sign() {                                //TODO know expected value
    byte[] expected = new byte[]{-127,-10,88,-97,-31,-28,99,55,-33,-83,10,-18,8,-83,-34,123,75,60,27,34,-41,3,62,-100,89,15,6,-38,82,-52,51,71,-14,-66,-92,88,-107,79,-22,125,3,-44,-11,112,110,60,-28,-77,54,-49,7,89,-66,-43,116,-67,83,-31,-34,119,101,-68,-44,105,-58,114,-2,-99,80,98,-21,-72,88,1,-103,-15,85,39,-50,-17,-63,-121,123,-121,-66,59,-27,-59,-6,-55,-32,-55,43,-126,43,-39,-33,2,-22,40,-18,-15,-83,26,-3,14,-29,-20,36,-17,-119,95,-63,99,111,109,25,-96,13,115,-113,75,48,61,-34,-75,86,18,76,-48,-96,-111,68,-58,-104,110,99,-19,125,34,14,3,82,-48,39,-4,35,-104,-43,-58,-35,-83,-18,38,-87,19,9,-74,114,-24,-33,69,76,105,125,78,108,-84,43,104,-95,124,38,-125,33,108,-122,-121,-104,113,98,17,-81,-91,-99,80,-123,58,6,108,-59,-41,-33,-39,98,125,112,-58,120,-32,-99,51,-29,-50,30,-22,94,11,113,-107,-119,-49,-52,83,-83,-101,-52,108,92,91,-78,17,-78,-42,71,2,-125,73,112,-72,79,51,2,-95,-88,54,-32,77,99,-76,60,-2,-90,100,50,101,-58,48,-30,-119,-76,-63,-21,-55,-112,76};
    byte[] actual = pkcs12SignatureToken.sign(DigestAlgorithm.SHA512, new byte[]{0x41});
    Assert.assertArrayEquals(expected, actual);
  }

  @Test
  public void closeSignatureTokenWhenSigning() {
    this.expectedException.expect(InvalidKeyException.class);
    this.expectedException.expectMessage("Private key entry is missing. Connection may be closed.");
    PKCS12SignatureToken pkcs12SignatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/signout.p12", "test".toCharArray());

    Assert.assertNotNull(pkcs12SignatureToken.sign(DigestAlgorithm.SHA512, new byte[]{0x41}));
    pkcs12SignatureToken.close();
    pkcs12SignatureToken.sign(DigestAlgorithm.SHA512, new byte[]{0x41});
  }

  @Test
  public void closeSignatureTokenWhenAskingCertificate() {
    this.expectedException.expect(InvalidKeyException.class);
    this.expectedException.expectMessage("Private key entry is missing. Connection may be closed.");
    PKCS12SignatureToken pkcs12SignatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/signout.p12", "test".toCharArray());
    Assert.assertNotNull(pkcs12SignatureToken.getCertificate());
    pkcs12SignatureToken.close();
    pkcs12SignatureToken.getCertificate();
  }


}
