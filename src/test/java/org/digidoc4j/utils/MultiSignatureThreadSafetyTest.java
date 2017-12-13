package org.digidoc4j.utils;

import java.io.ByteArrayInputStream;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.testutils.TestDataBuilder;
import org.digidoc4j.testutils.TestSigningHelper;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This test was created when SKOnlineOCSPSource had a thread safety problem with its nonce checking code;
 * the problem would often manifest when signing 2 signatures in a row with a specific set of certificates.
 * Now that the cause is fixed, this test may need to be simplified or deleted.
 */
public class MultiSignatureThreadSafetyTest extends AbstractSigningTests {

  @Test
  public void signingTwiceDoesNotCauseAThreadingProblemWithSkOnlineOCSPSource() throws InterruptedException {
    for (int i = 0; i < 2; i++) {
      sign();
    }
  }

  private void sign() {
    Configuration conf = new Configuration(Configuration.Mode.TEST);
    Container container = ContainerBuilder.
        aContainer("BDOC").
        withConfiguration(conf).
        withDataFile(new ByteArrayInputStream("file contents".getBytes()), "file.txt", "application/octet-stream").
        build();

    TestDataBuilder.signContainer(container, SignatureProfile.LT);
  }
}
