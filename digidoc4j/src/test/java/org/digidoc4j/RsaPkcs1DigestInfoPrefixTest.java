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

import eu.europa.esig.dss.spi.DSSUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.digidoc4j.test.util.TestSigningUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RsaPkcs1DigestInfoPrefixTest extends AbstractTest {

  @BeforeAll
  static void setUpProvider() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @ParameterizedTest
  @EnumSource(DigestAlgorithm.class)
  void rawRsaSigning_WhenSignableDigestIsPaddedWithDigestAlgorithmDigestInfoPrefix_ProducesValidRsaPkcs1Signature(
          DigestAlgorithm digestAlgorithm
  ) throws Exception {
    byte[] dataToSign = getDataToSign();
    byte[] messageDigest = DSSUtils.digest(digestAlgorithm.getDssDigestAlgorithm(), dataToSign);
    byte[] digestInfoPaddedMessageDigest = ArrayUtils.addAll(digestAlgorithm.digestInfoPrefix(), messageDigest);
    String digestSpecificSignatureAlgorithm = digestAlgorithm.getDssDigestAlgorithm().getName() + "withRSA";
    PrivateKey privateKey = TestSigningUtil.getSigningPrivateKey();

    byte[] manuallyPaddedSignature = TestSigningUtil.encrypt(privateKey, digestInfoPaddedMessageDigest);

    byte[] providerGeneratedSignature = TestSigningUtil.encrypt(privateKey, dataToSign, digestAlgorithm);
    assertArrayEquals(providerGeneratedSignature, manuallyPaddedSignature);
    assertVerify(digestSpecificSignatureAlgorithm, dataToSign, manuallyPaddedSignature);
  }

  private static byte[] getDataToSign() {
    return "This is a test string.".getBytes(StandardCharsets.UTF_8);
  }

  private static void assertVerify(String signatureAlgorithm, byte[] dataToSign, byte[] signatureBytes) throws Exception {
    Signature signature = Signature.getInstance(signatureAlgorithm);
    signature.initVerify(TestSigningUtil.getSigningCertificate().getPublicKey());
    signature.update(dataToSign);

    assertTrue(signature.verify(signatureBytes), "Expected signature to be valid");
  }

}
