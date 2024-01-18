/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.ddoc.factory;

import eu.europa.esig.dss.spi.DSSRevocationUtils;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.digidoc4j.test.util.TestKeyPairUtil;
import org.digidoc4j.test.util.TestOcspUtil;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.PrivateKey;
import java.security.Security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

/**
 * This test covers the changes in the {@link BouncyCastleNotaryFactory#responderIDtoString(BasicOCSPResp)} of the old
 * {@code ddoc4j} module, caused by the update to Bouncy Castle version 1.76 (jdk18on) from the previously used version
 * of 1.70 (jdk15on).
 */
public class BouncyCastleNotaryFactoryResponderIdToStringTest {

  @BeforeClass
  public static void setUpStatic() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void responderIDtoString_WhenBasicOcspRespIsNull_ReturnsNull() {
    String result = BouncyCastleNotaryFactory.responderIDtoString(null);

    assertThat(result, nullValue());
  }

  @Test
  public void responderIDtoString_WhenBasicOcspRespResponderIdIsByNameEsteidSkOcspResponder_ReturnsIdStringByName() {
    BasicOCSPResp basicOcspResp = loadBasicOcspResp(
            "MIIBsAoBAKCCAakwggGlBgkrBgEFBQcwAQEEggGWMIIBkjCB/KFsMGoxCzAJBgNV" +
                    "BAYTAkVFMQ8wDQYDVQQKEwZFU1RFSUQxDTALBgNVBAsTBE9DU1AxITAfBgNVBAMT" +
                    "GEVTVEVJRC1TSyBPQ1NQIFJFU1BPTkRFUjEYMBYGCSqGSIb3DQEJARYJcGtpQHNr" +
                    "LmVlGA8yMDAyMTAwNzExMTA0N1owVDBSMD0wCQYFKw4DAhoFAAQUJk2D09/TR+gq" +
                    "txo/O5Aq31AEQNwEFHgXtQX5s1jNWYzeZ15EBkx1hmldAgQ9nDIMgAAYDzIwMDIx" +
                    "MDA3MTExMDQ2WqElMCMwIQYJKwYBBQUHMAECBBT7MmTl4RavU7lCjNHBMHE4e1cZ" +
                    "YTANBgkqhkiG9w0BAQUFAAOBgQI3ixQNVnmY8xgUe3FcrWPeqfr0fb4yvm5oxvE+" +
                    "hkOzhRL/DB4mnaJhG+hGoV8fQPYwJpAU5lcL5SMWPdMqPWA4bUUn8Sz5Opf8SvDi" +
                    "p9ZOG3YcqUIyRArXhYe8QJ10HLSIex+nvuP6I/T9N/lPQOTK1kvBK5bikTIadbrk" +
                    "xi8VzA=="
    );

    String result = BouncyCastleNotaryFactory.responderIDtoString(basicOcspResp);

    assertThat(result, equalTo(
            "byName: C=EE,O=ESTEID,OU=OCSP,CN=ESTEID-SK OCSP RESPONDER,E=pki@sk.ee"
    ));
  }

  @Test
  public void responderIDtoString_WhenBasicOcspRespResponderIdIsByNameKlass3SkOcspResponder_ReturnsIdStringByName() {
    BasicOCSPResp basicOcspResp = loadBasicOcspResp(
            "MIIBxAoBAKCCAb0wggG5BgkrBgEFBQcwAQEEggGqMIIBpjCCAQ+hfzB9MQswCQYD" +
                    "VQQGEwJFRTEiMCAGA1UEChMZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czENMAsG" +
                    "A1UECxMET0NTUDEhMB8GA1UEAxMYS0xBU1MzLVNLIE9DU1AgUkVTUE9OREVSMRgw" +
                    "FgYJKoZIhvcNAQkBFglwa2lAc2suZWUYDzIwMDMxMDI0MTA1NzE5WjBUMFIwPTAJ" +
                    "BgUrDgMCGgUABBRah9vDBESosFQzbhsgnloU2ACuAgQU5T8MnXE9b7wZv5r0br8J" +
                    "/kDrnZYCBD9u6LKAABgPMjAwMzEwMjQxMDU3MTlaoSUwIzAhBgkrBgEFBQcwAQIE" +
                    "FEoJJm7/2OlQqcaFCtclJmGORxWrMA0GCSqGSIb3DQEBBQUAA4GBAJfnFWPdzjLZ" +
                    "OefeZa8R4S3ASHgeU85vWDZ+Klio+7dn6fap85BSvHn63sYIccVvO1QsSahu1yIg" +
                    "cRzVxkCNYZabbS0Cjzf+dlV4U2vIlidO6Y2q2kgzaeLvfBsPm+tcQ2YPcw9vKKrw" +
                    "DjH6h3QhUAC67mi91tRCYWfVo3rwVjE1"
    );

    String result = BouncyCastleNotaryFactory.responderIDtoString(basicOcspResp);

    assertThat(result, equalTo(
            "byName: C=EE,O=AS Sertifitseerimiskeskus,OU=OCSP,CN=KLASS3-SK OCSP RESPONDER,E=pki@sk.ee"
    ));
  }

  @Test
  public void responderIDtoString_WhenBasicOcspRespResponderIdIsByNameCustomSubjectDn_ReturnsIdStringByName() {
    String customSubjectDn = "CN=CUSTOM,O=TEST,C=EE";
    BasicOCSPResp basicOcspResp = buildBasicOcspResp(new RespID(new X500Name(customSubjectDn)));

    String result = BouncyCastleNotaryFactory.responderIDtoString(basicOcspResp);

    assertThat(result, equalTo(
            "byName: " + customSubjectDn
    ));
  }

  @Test
  public void responderIDtoString_WhenBasicOcspRespResponderIdIsByKeyCustomKeyHash_ReturnsIdStringByKey() {
    ASN1OctetString customKeyHashOctets = new DEROctetString(new byte[]{
            0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef
    });
    BasicOCSPResp basicOcspResp = buildBasicOcspResp(new RespID(new ResponderID(customKeyHashOctets)));

    String result = BouncyCastleNotaryFactory.responderIDtoString(basicOcspResp);

    assertThat(result, equalTo(
            "byKey: 0123456789abcdef"
    ));
  }

  private static BasicOCSPResp loadBasicOcspResp(String ocspResponseBase64) {
    try {
      byte[] binary = Base64.decodeBase64(ocspResponseBase64);
      return DSSRevocationUtils.loadOCSPFromBinaries(binary);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to parse OCSP response", e);
    }
  }

  private static BasicOCSPResp buildBasicOcspResp(RespID respId) {
    BasicOCSPRespBuilder basicOCSPRespBuilder = TestOcspUtil.createBasicOCSPRespBuilder(respId);

    AsymmetricCipherKeyPair keyPair = TestKeyPairUtil.generateEcKeyPair("secp384r1");
    PrivateKey privateKey = TestKeyPairUtil.toPrivateKey(keyPair.getPrivate());
    ContentSigner ocspSigner = TestOcspUtil.createOcspSigner(privateKey, "SHA384withECDSA");

    return TestOcspUtil.buildBasicOCSPResp(basicOCSPRespBuilder, ocspSigner);
  }

}
