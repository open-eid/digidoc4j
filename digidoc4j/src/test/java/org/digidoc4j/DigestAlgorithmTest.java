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

import org.digidoc4j.exceptions.TechnicalException;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.util.Objects;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DigestAlgorithmTest {

  @Test
  void testGetDigestAlgorithmUriFromDssDigestAlgorithmSucceeds() {
    Stream.of(eu.europa.esig.dss.enumerations.DigestAlgorithm.values())
            .filter(dssDigestAlgorithm -> Objects.nonNull(dssDigestAlgorithm.getUri()))
            .forEach(dssDigestAlgorithm -> {
              URL digestAlgorithmUri = DigestAlgorithm.getDigestAlgorithmUri(dssDigestAlgorithm);

              assertNotNull(digestAlgorithmUri);
              assertEquals(dssDigestAlgorithm.getUri(), digestAlgorithmUri.toString());
            });
  }

  @Test
  void testGetDigestAlgorithmUriFromDssDigestAlgorithmFailsWhenNoUriSpecified() {
    Stream.of(eu.europa.esig.dss.enumerations.DigestAlgorithm.values())
            .filter(dssDigestAlgorithm -> Objects.isNull(dssDigestAlgorithm.getUri()))
            .forEach(dssDigestAlgorithm -> {
              TechnicalException caughtException = assertThrows(
                      TechnicalException.class,
                      () -> DigestAlgorithm.getDigestAlgorithmUri(dssDigestAlgorithm)
              );

              assertEquals(
                      "No digest algorithm URI specified for " + dssDigestAlgorithm.getName(),
                      caughtException.getMessage()
              );
            });
  }

  @Test
  void findByOid_WhenOidStringMatchesExistingAlgorithm_ReturnsExpectedDigestAlgorithm() {
    Stream.of(DigestAlgorithm.values())
            .forEach(digestAlgorithm -> {
              String oid = digestAlgorithm.getDssDigestAlgorithm().getOid();

              DigestAlgorithm result = DigestAlgorithm.findByOid(oid);

              assertSame(digestAlgorithm, result);
            });
  }

    @Test
    void findByOid_WhenOidStringDoesNotMatchAlgorithm_ReturnsNull() {
      DigestAlgorithm result = DigestAlgorithm.findByOid("Non.Existent.OID");

      assertNull(result);
    }

}
