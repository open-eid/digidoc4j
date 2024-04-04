/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.bdoc;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Created by Andrei on 26.04.2017.
 */

public class SignatureTimeTest extends AbstractTest {

  @Test
  public void signatureProfileLTTest() {
    Instant notBefore = truncatedCurrentTime();
    Container container = createNonEmptyContainerBy(Container.DocumentType.ASICE);
    AsicESignature signature = createSignatureBy(Container.DocumentType.ASICE, SignatureProfile.LT, pkcs12SignatureToken);
    container.addSignature(signature);
    TestAssert.assertTimeBetweenNotBeforeAndNow(signature.getClaimedSigningTime(), notBefore, Duration.ZERO);
    TestAssert.assertTimeBetweenNotBeforeAndNow(signature.getTrustedSigningTime(), notBefore, Duration.ofMinutes(1L));
  }

  @Test
  public void signatureProfileLTATest() {
    Instant notBefore = truncatedCurrentTime();
    Container container = createNonEmptyContainerBy(Container.DocumentType.ASICE);
    AsicESignature signature = createSignatureBy(Container.DocumentType.ASICE, SignatureProfile.LTA, pkcs12SignatureToken);
    container.addSignature(signature);
    TestAssert.assertTimeBetweenNotBeforeAndNow(signature.getClaimedSigningTime(), notBefore, Duration.ZERO);
    TestAssert.assertTimeBetweenNotBeforeAndNow(signature.getTrustedSigningTime(), notBefore, Duration.ofMinutes(1L));
  }

  @Test
  public void signatureProfileB_BESTest() {
    Instant notBefore = truncatedCurrentTime();
    Container container = createNonEmptyContainerBy(Container.DocumentType.ASICE);
    AsicESignature signature = createSignatureBy(Container.DocumentType.ASICE, SignatureProfile.B_BES, pkcs12SignatureToken);
    container.addSignature(signature);
    TestAssert.assertTimeBetweenNotBeforeAndNow(signature.getClaimedSigningTime(), notBefore, Duration.ZERO);
    Assert.assertNull(signature.getTrustedSigningTime());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

  private static Instant truncatedCurrentTime() {
    return Instant.now().truncatedTo(ChronoUnit.SECONDS);
  }

}
