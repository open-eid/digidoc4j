/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.utils;

import java.io.ByteArrayInputStream;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.jupiter.api.Test;

/**
 * This test was created when SKOnlineOCSPSource had a thread safety problem with its nonce checking code;
 * the problem would often manifest when signing 2 signatures in a row with a specific set of certificates.
 * Now that the cause is fixed, this test may need to be simplified or deleted.
 */
class MultiSignatureThreadSafetyTest extends AbstractTest {

  @Test
  void signingTwiceDoesNotCauseAThreadingProblemWithSkOnlineOCSPSource() {
    for (int i = 0; i < 2; i++) {
      sign();
    }
  }

  /*
   * ACCESSORS
   */

  private void sign() {
    configuration = new Configuration(Configuration.Mode.TEST);
    Container container = ContainerBuilder.aContainer().withConfiguration(configuration)
        .withDataFile(new ByteArrayInputStream("file contents".getBytes()), "file.txt", "application/octet-stream").
        build();
    TestDataBuilderUtil.signContainer(container, SignatureProfile.LT);
  }

}
