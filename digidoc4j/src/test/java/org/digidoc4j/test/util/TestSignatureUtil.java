/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.test.util;

import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;

public final class TestSignatureUtil {

  public static String getEcdsaSignatureMethodUri(DigestAlgorithm digestAlgorithm) {
    return eu.europa.esig.dss.enumerations.SignatureAlgorithm
            .getAlgorithm(eu.europa.esig.dss.enumerations.EncryptionAlgorithm.ECDSA, digestAlgorithm.getDssDigestAlgorithm())
            .getUri();
  }

  public static String getRsassaPssSignatureMethodUri(DigestAlgorithm digestAlgorithm) {
    return eu.europa.esig.dss.enumerations.SignatureAlgorithm
            .getAlgorithm(eu.europa.esig.dss.enumerations.EncryptionAlgorithm.RSASSA_PSS, digestAlgorithm.getDssDigestAlgorithm())
            .getUri();
  }

  public static void assertSignatureContainsDigestMethod(Signature signature, DigestAlgorithm digestAlgorithm) {
    assertThat(new String(signature.getAdESSignature(), StandardCharsets.UTF_8), containsString("Algorithm=\"" + digestAlgorithm + "\""));
  }

}
