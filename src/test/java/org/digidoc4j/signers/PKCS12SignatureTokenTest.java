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

import java.security.cert.CertificateEncodingException;

import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.X509Cert;
import org.junit.Assert;
import org.junit.Test;

public class PKCS12SignatureTokenTest extends AbstractTest {

  @Test
  public void getCertificate() throws CertificateEncodingException {
    X509Cert x509Cert = new X509Cert(this.pkcs12SignatureToken.getCertificate());
    Assert.assertEquals("MIIFrjCCA5agAwIBAgIQUwvkG7xZfERXDit8E7z6DDANBgkqhkiG9w0BAQsFADBr" +
            "MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1" +
            "czEXMBUGA1UEYQwOTlRSRUUtMTA3NDcwMTMxHzAdBgNVBAMMFlRFU1Qgb2YgRVNU" +
            "RUlELVNLIDIwMTUwHhcNMTYwNDEzMTEyMDI4WhcNMjEwNDEyMjA1OTU5WjCBtDEL" +
            "MAkGA1UEBhMCRUUxDzANBgNVBAoMBkVTVEVJRDEaMBgGA1UECwwRZGlnaXRhbCBz" +
            "aWduYXR1cmUxMTAvBgNVBAMMKMW9w5VSSU7DnFfFoEtZLE3DhFLDnC1Mw5bDllos" +
            "MTE0MDQxNzY4NjUxFzAVBgNVBAQMDsW9w5VSSU7DnFfFoEtZMRYwFAYDVQQqDA1N" +
            "w4RSw5wtTMOWw5ZaMRQwEgYDVQQFEwsxMTQwNDE3Njg2NTCCASIwDQYJKoZIhvcN" +
            "AQEBBQADggEPADCCAQoCggEBAJrWrja4BY6nlDXf/46So37NcJoDAB8d6pZr2XxM" +
            "4cCv3MqAKAuf8oew38jc+/20oBiMo9bSWfTrjCtunuyJxBi6/xX1SwXqXpCIcAeA" +
            "tL8SA4NRuWQGEFxGRJtPUNpzVkiIBI5u+yENpxvGFOW7777u0E7E3p/Jx6Y6HflI" +
            "CQPm48zjzeBytJ+m6v6EdObnOpeJtusaZ+Yg/hmrCRRgJeRtnjJIw5LmLrjqm185" +
            "BFtgwFH0J8iAr18FSua5yLP343s4vZx8np1NqmdJrlHt5IjX2D3+QAObJmh/U+id" +
            "oNdThlJlst/cj5/y496vR+PhSWIWzqv//xYH41qIkXDjD+UCAwEAAaOCAQIwgf8w" +
            "CQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBkAwOwYDVR0gBDQwMjAwBgkrBgEEAc4f" +
            "AwEwIzAhBggrBgEFBQcCARYVaHR0cHM6Ly93d3cuc2suZWUvY3BzMB0GA1UdDgQW" +
            "BBQ27kyYhup5RKLxTM1gxY+BDz/N0jAiBggrBgEFBQcBAwQWMBQwCAYGBACORgEB" +
            "MAgGBgQAjkYBBDAfBgNVHSMEGDAWgBRJwPJEOWXVm0Y7DThgg7HWLSiGpjBBBgNV" +
            "HR8EOjA4MDagNKAyhjBodHRwOi8vd3d3LnNrLmVlL2NybHMvZXN0ZWlkL3Rlc3Rf" +
            "ZXN0ZWlkMjAxNS5jcmwwDQYJKoZIhvcNAQELBQADggIBAHUUiGcIgXB3INd78mGF" +
            "yIz+u8+TLPON0va0mRuugy1TEH0eWZqNhv2+7vvzd8CLoOp4aHrUwvx7zGaND/bO" +
            "w4dC1dO5zsXh1EziNAfaNqzYP2QQ4BckqZeGl0+d7OVyP5/HgZOYI90qYLvkjWSn" +
            "eSFXZ2BN8Jku6l0dUnhsQqCoLKl0j4F+1u+GwC9pjzm2aVoYRs3CcNgkAa1O3SKK" +
            "9PXpz/chFE1dfvT8xPagroVkzDCZ4o6Rp+8OPBPYacQhdIH6DyagPcbdKz1S0EC8" +
            "q+7qm1C8bM05oyYfkoBLU6afgRGHcpRMFQRBnsu7o1LQIMsRF5dWWTqL4FLLw6iF" +
            "exZA6z3HMilu+yolLxURaD3oWMcWzLKi0Ic88T8LNyz5ksWDDZXAoso0ZDTAh/Da" +
            "FEdeQs9MnOkGzrvswrEG2MUs33XHhp988TWgRQGAJU/JZQR057I/UxfikYRhZ5oM" +
            "7qPBy4oDh3VlhMsY5yHuK400Xi202xoXVS+VG33xB7KCvbwuemZSlVewxTX0ZJg5" +
            "qTcwIXRMlsWffqyVWpnxjnvWmqO01nrbgjlpBAbDDT2R/JXPOjVpgjhQGEmNmVj3" +
            "OvfjvLlXXP7CZ4Vxwxy0aBPPvVHoyWjFycsqm4EFGSGkcB17NcP3dlj7ZwloBobg" +
            "ittrqXcLf8qik7sGgHnaa7Cc",
        Base64.encodeBase64String(x509Cert.getX509Certificate().getEncoded()));
  }

  @Test
  public void sign() {                                //TODO know expected value
    byte[] expected = new byte[]{40, -84, -43, -95, -8, 46, -27, -2, 41, 80, -96, -74, 125, 37, -11, 85, -22, 64, -87, 122, 41, -29, 91, -35, 104, 60, 86, -98, -65, -101, 81, 74, -10, 35, -24, -115, -14, 115, -58, -53, -28, -53, 47, -82, 74, -21, 88, -111, -31, 47, 112, 71, 41, -32, 120, 119, 109, 34, -96, 124, -61, -5, 112, 114, 122, 1, 30, -105, 112, 67, 116, -32, -44, -123, -43, 26, 63, -28, -41, 82, -79, -32, 98, 93, 20, -76, -94, 105, 40, -95, -1, -97, -33, 88, 31, 92, -115, -114, 118, -94, 3, 126, -25, -100, -84, 72, -84, 51, -122, -59, -72, 0, 123, 68, -116, 91, -105, 7, 81, -106, 10, 58, -39, 53, 109, -48, -121, 4, -111, 32, -127, -74, -3, -73, -57, -12, 114, 126, -20, -40, 76, -58, 119, -108, 85, -124, 97, -55, -82, -120, -94, -40, -10, -96, -60, 29, 84, 55, 12, 77, 27, -117, -3, 84, 39, -24, -66, -89, -5, 51, -64, -53, -16, -43, -53, 63, -59, -32, 48, 82, -85, -124, -107, -85, 43, 37, 62, -63, 42, -8, 86, -79, 42, -119, -37, 30, 6, -71, 30, -63, 98, 109, 56, 74, 69, -14, -44, 104, 86, -87, 37, 109, 91, 59, -58, 33, 81, -69, -50, -82, 121, 69, -99, 18, 51, -63, 116, -56, -26, 96, -81, -17, -106, -57, 45, -15, 11, -39, -24, 121, -59, -38, 83, -3, 21, -104, -102, 116, 44, 108, -7, 79, -49, -106, 28, -82};
    byte[] actual = this.pkcs12SignatureToken.sign(DigestAlgorithm.SHA512, new byte[]{0x41});
    Assert.assertArrayEquals(expected, actual);
  }

}
