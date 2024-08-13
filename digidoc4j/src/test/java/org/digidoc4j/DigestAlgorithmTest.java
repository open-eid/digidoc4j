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
import org.junit.Assert;
import org.junit.Test;

import java.net.URL;
import java.util.Objects;
import java.util.stream.Stream;

public class DigestAlgorithmTest {

  @Test
  public void testGetDigestAlgorithmUriFromDssDigestAlgorithmSucceeds() {
    Stream.of(eu.europa.esig.dss.enumerations.DigestAlgorithm.values())
            .filter(dssDigestAlgorithm -> Objects.nonNull(dssDigestAlgorithm.getUri()))
            .forEach(dssDigestAlgorithm -> {
              URL digestAlgorithmUri = DigestAlgorithm.getDigestAlgorithmUri(dssDigestAlgorithm);

              Assert.assertNotNull(digestAlgorithmUri);
              Assert.assertEquals(dssDigestAlgorithm.getUri(), digestAlgorithmUri.toString());
            });
  }

  @Test
  public void testGetDigestAlgorithmUriFromDssDigestAlgorithmFailsWhenNoUriSpecified() {
    Stream.of(eu.europa.esig.dss.enumerations.DigestAlgorithm.values())
            .filter(dssDigestAlgorithm -> Objects.isNull(dssDigestAlgorithm.getUri()))
            .forEach(dssDigestAlgorithm -> {
              TechnicalException caughtException = Assert.assertThrows(
                      TechnicalException.class,
                      () -> DigestAlgorithm.getDigestAlgorithmUri(dssDigestAlgorithm)
              );

              Assert.assertEquals(
                      "No digest algorithm URI specified for " + dssDigestAlgorithm.getName(),
                      caughtException.getMessage()
              );
            });
  }

  @Test
  public void findByOid_WhenOidStringMatchesExistingAlgorithm_ReturnsExpectedDigestAlgorithm() {
    Stream.of(DigestAlgorithm.values())
            .forEach(digestAlgorithm -> {
              String oid = digestAlgorithm.getDssDigestAlgorithm().getOid();

              DigestAlgorithm result = DigestAlgorithm.findByOid(oid);

              Assert.assertSame(digestAlgorithm, result);
            });
  }

    @Test
    public void findByOid_WhenOidStringDoesNotMatchAlgorithm_ReturnsNull() {
      DigestAlgorithm result = DigestAlgorithm.findByOid("Non.Existent.OID");

      Assert.assertNull(result);
    }

}
