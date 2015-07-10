package org.digidoc4j.utils;

import java.io.ByteArrayInputStream;

import org.digidoc4j.Container;
import org.digidoc4j.impl.BDocContainer;
import org.junit.Test;

/** 
 * This test was created when SKOnlineOCSPSource had a thread safety problem with its nonce checking code;
 * the problem would often manifest when signing 2 signatures in a row with a specific set of certificates.
 * Now that the cause is fixed, this test may need to be simplified or deleted. 
 */
public class MultiSignatureThreadSafetyTest extends AbstractSigningTests {
    @Test
    public void signingTwiceDoesNotCauseAThreadingProblemWithSkOnlineOCSPSource() throws InterruptedException {
        for(int i = 0; i < 2; i++) {
            sign();
        }
    }

    protected void sign() {
        BDocContainer container = (BDocContainer) Container.create(createDigiDoc4JConfiguration());
        container.addDataFile(new ByteArrayInputStream("file contents".getBytes()), "file.txt", "application/octet-stream");
        byte[] hashToSign = prepareSigning(container, CertificatesForTests.SIGN_CERT, createSignatureParameters());
        byte[] signatureValue = signWithRsa(CertificatesForTests.PRIVATE_KEY_FOR_SIGN_CERT, hashToSign);
        container.signRaw(signatureValue);
    }
}
