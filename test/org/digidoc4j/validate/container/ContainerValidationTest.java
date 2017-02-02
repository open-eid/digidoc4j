package org.digidoc4j.validate.container;

import java.io.FileInputStream;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.junit.Test;

public class ContainerValidationTest extends DigiDoc4JTestHelper {

  @Test(expected = InvalidDataFileException.class)
  public void validateContainer() throws Exception {

    Configuration configuration = new Configuration(Configuration.Mode.TEST);

    FileInputStream fis = new FileInputStream(
        "testFiles/special-char-files/dds_acrobat.pdf");

    Container container = ContainerBuilder.aContainer("BDOC")
        .withConfiguration(configuration).withDataFile(fis,
            "xxx,%2003:1737,%2031.08.2015.a.pdf", "application/pdf")
        .usingTempDirectory("C:/DigiDocUtilTest").build();

    String privateKeyPath = "testFiles/signout.p12";
    char[] password = "test".toCharArray();
    PKCS12SignatureToken testSignatureToken = new PKCS12SignatureToken(
        privateKeyPath, password);

    Signature signature = SignatureBuilder.aSignature(container)
        .withSignatureDigestAlgorithm(DigestAlgorithm.SHA256)
        .withSignatureProfile(SignatureProfile.LT_TM)
        .withSignatureToken(testSignatureToken).invokeSigning();

    container.addSignature(signature);

    container.saveAsFile("testFiles/andrei-test-container.bdoc");

    fis.close();
  }
}
