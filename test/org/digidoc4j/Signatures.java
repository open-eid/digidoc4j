package org.digidoc4j;

public class Signatures {
  public static final String XADES_SIGNATURE = "  <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"S0\">\n" +
      "    <ds:SignedInfo>\n" +
      "      <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
      "      <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n" +
      "      <ds:Reference Id=\"detached-ref-id\" URI=\"test.txt\">\n" +
      "        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
      "        <ds:DigestValue>tYpuWTmktpzSwRM8cxRlZfY4aw4wqr4vkXKPs9lwxP4=</ds:DigestValue>\n" +
      "      </ds:Reference>\n" +
      "      <ds:Reference Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#xades-S0\">\n" +
      "        <ds:Transforms>\n" +
      "          <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
      "        </ds:Transforms>\n" +
      "        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
      "        <ds:DigestValue>FRivrptdyLddxErkDScuto+iYageAlte+ZPLjNeDJpo=</ds:DigestValue>\n" +
      "      </ds:Reference>\n" +
      "    </ds:SignedInfo>\n" +
      "    <ds:SignatureValue Id=\"value-S0\">\n" +
      "      BvYEpUkI7GA0prgCLM3auNtoxg0/H35xNJsK6Aw3Gt0eLnQ4PUHYUTU0Nvq/RrTYuuWIu/e07WIa1GT1qKb2VucUVVysqxpN7LViQx0vgLGr4F8dj1KFt1JLnOFSVHuAWX9iy1gZ8TpcamOpWRejzyc4D5CIBiC/seI4io6hs+K25WBsJPMqX2Eh/WLjlzsaVq75nNn8UQ7Jj88rayewavuQZTOWpB/4X7Wc3Gdyz7cwuQO4r5WVJhXTV0jAZQPItmlQJlxGTTHT1MOT7MH3sDlVGXcPEklGQNaib3LJQM2dZDZ4ZsdaGSaVYsr9vOHWGZCJx/gwmnTxOmhR9psy+w==\n" +
      "    </ds:SignatureValue>\n" +
      "    <ds:KeyInfo>\n" +
      "      <ds:X509Data>\n" +
      "        <ds:X509Certificate>\n" +
      "          MIIFEzCCA/ugAwIBAgIQSXxaK/qTYahTT77Z9I56EjANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEfMB0GA1UEAwwWVEVTVCBvZiBFU1RFSUQtU0sgMjAxMTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlMB4XDTE0MDQxNzExNDUyOVoXDTE2MDQxMjIwNTk1OVowgbQxCzAJBgNVBAYTAkVFMQ8wDQYDVQQKDAZFU1RFSUQxGjAYBgNVBAsMEWRpZ2l0YWwgc2lnbmF0dXJlMTEwLwYDVQQDDCjFvcOVUklOw5xXxaBLWSxNw4RSw5wtTMOWw5ZaLDExNDA0MTc2ODY1MRcwFQYDVQQEDA7FvcOVUklOw5xXxaBLWTEWMBQGA1UEKgwNTcOEUsOcLUzDlsOWWjEUMBIGA1UEBRMLMTE0MDQxNzY4NjUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChn9qVaA+x3RkDBrD5ujwfnreK5/Nb+Nvo9Vg5OLMn3JKUoUhFX6A/q5lBUylK/CU/lNRTv/kicqnu1aCyAiW0XVYk8jrOI1wRbHeyBMq/5gVm/vbbRtMi/XGLkgMZ5UDxY0QZfmu8wlRJ8164zRNocuUJLLXWOB6vda2RRXC3Cix4TDvQwGmPrQQJ8dzDIJEkLS7NCLBTcndm7buQegRc043gKMjUmRhGZEzF4oJa4pMfXqeSa+PUtrNyNNNQaOwTH29R8aFfGU2xorVvxoUieNipyWMEz8BTUGwwIceapWi77loBV/VQfStXnQNu/s6BC04ss43O6sK70MB1qlRZAgMBAAGjggFmMIIBYjAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIGQDCBmQYDVR0gBIGRMIGOMIGLBgorBgEEAc4fAwEBMH0wWAYIKwYBBQUHAgIwTB5KAEEAaQBuAHUAbAB0ACAAdABlAHMAdABpAG0AaQBzAGUAawBzAC4AIABPAG4AbAB5ACAAZgBvAHIAIAB0AGUAcwB0AGkAbgBnAC4wIQYIKwYBBQUHAgEWFWh0dHA6Ly93d3cuc2suZWUvY3BzLzAdBgNVHQ4EFgQUEjVsOkaNOGG0GlcF4icqxL0u4YcwIgYIKwYBBQUHAQMEFjAUMAgGBgQAjkYBATAIBgYEAI5GAQQwHwYDVR0jBBgwFoAUQbb+xbGxtFMTjPr6YtA0bW0iNAowRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL3d3dy5zay5lZS9yZXBvc2l0b3J5L2NybHMvdGVzdF9lc3RlaWQyMDExLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAYTJLbScA3+Xh/s29Qoc0cLjXW3SVkFP/U71/CCIBQ0ygmCAXiQIp/7X7JonY4aDz5uTmq742zZgq5FA3c3b4NtRzoiJXFUWQWZOPE6Ep4Y07Lpbn04sypRKbVEN9TZwDy3elVq84BcX/7oQYliTgj5EaUvpe7MIvkK4DWwrk2ffx9GRW+qQzzjn+OLhFJbT/QWi81Q2CrX34GmYGrDTC/thqr5WoPELKRg6a0v3mvOCVtfIxJx7NKK4B6PGhuTl83hGzTc+Wwbaxwjqzl/SUwCNd2R8GV8EkhYH8Kay3Ac7Qx3agrJJ6H8j+h+nCKLjIdYImvnznKyR0N2CRc/zQ+g==\n" +
      "        </ds:X509Certificate>\n" +
      "      </ds:X509Data>\n" +
      "    </ds:KeyInfo>\n" +
      "    <ds:Object>\n" +
      "      <xades:QualifyingProperties xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" Target=\"#S0\">\n" +
      "        <xades:SignedProperties Id=\"xades-S0\">\n" +
      "          <xades:SignedSignatureProperties>\n" +
      "            <xades:SigningTime>2014-07-15T09:20:02Z</xades:SigningTime>\n" +
      "            <xades:SigningCertificate>\n" +
      "              <xades:Cert>\n" +
      "                <xades:CertDigest>\n" +
      "                  <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n" +
      "                  <ds:DigestValue>N9OdruanX8xd0jmQiqaTjnIb7Mk=</ds:DigestValue>\n" +
      "                </xades:CertDigest>\n" +
      "                <xades:IssuerSerial>\n" +
      "                  <ds:X509IssuerName>1.2.840.113549.1.9.1=#1609706b6940736b2e6565,CN=TEST of ESTEID-SK 2011,O=AS\n" +
      "                    Sertifitseerimiskeskus,C=EE\n" +
      "                  </ds:X509IssuerName>\n" +
      "                  <ds:X509SerialNumber>97679317403981919837045055800589842962</ds:X509SerialNumber>\n" +
      "                </xades:IssuerSerial>\n" +
      "              </xades:Cert>\n" +
      "            </xades:SigningCertificate>\n" +
      "          </xades:SignedSignatureProperties>\n" +
      "          <xades:SignedDataObjectProperties>\n" +
      "            <xades:DataObjectFormat ObjectReference=\"#detached-ref-id\">\n" +
      "              <xades:MimeType>text/plain</xades:MimeType>\n" +
      "            </xades:DataObjectFormat>\n" +
      "          </xades:SignedDataObjectProperties>\n" +
      "        </xades:SignedProperties>\n" +
      "        <xades:UnsignedProperties>\n" +
      "          <xades:UnsignedSignatureProperties>\n" +
      "            <xades:SignatureTimeStamp Id=\"time-stamp-token-38aa15ea-76d1-4d41-baeb-5972142e6747\">\n" +
      "              <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
      "              <xades:EncapsulatedTimeStamp Id=\"time-stamp-token-38aa15ea-76d1-4d41-baeb-5972142e6747\">\n" +
      "                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\n" +
      "              </xades:EncapsulatedTimeStamp>\n" +
      "            </xades:SignatureTimeStamp>\n" +
      "            <xades:CertificateValues/>\n" +
      "          </xades:UnsignedSignatureProperties>\n" +
      "        </xades:UnsignedProperties>\n" +
      "      </xades:QualifyingProperties>\n" +
      "    </ds:Object>\n" +
      "  </ds:Signature>";
}
