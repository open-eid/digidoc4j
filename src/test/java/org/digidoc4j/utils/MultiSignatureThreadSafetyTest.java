package org.digidoc4j.utils;

import java.io.ByteArrayInputStream;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Test;

/**
 * This test was created when SKOnlineOCSPSource had a thread safety problem with its nonce checking code;
 * the problem would often manifest when signing 2 signatures in a row with a specific set of certificates.
 * Now that the cause is fixed, this test may need to be simplified or deleted.
 */
public class MultiSignatureThreadSafetyTest extends AbstractTest {

  @Test
  public void signingTwiceDoesNotCauseAThreadingProblemWithSkOnlineOCSPSource() throws InterruptedException {
    for (int i = 0; i < 2; i++) {
      this.sign();
    }
  }

  /*
   * ACCESSORS
   */

  private void sign() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    Container container = ContainerBuilder.aContainer().withConfiguration(this.configuration)
        .withDataFile(new ByteArrayInputStream("file contents".getBytes()), "file.txt", "application/octet-stream").
        build();
    TestDataBuilderUtil.signContainer(container, SignatureProfile.LT);
  }

}
