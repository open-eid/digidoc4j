package org.digidoc4j.impl.bdoc;

import static org.junit.Assert.assertEquals;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.testutils.TestDataBuilder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Created by Andrei on 26.04.2017.
 */
public class SignatureTimeTest {

  static Configuration configuration = new Configuration(Configuration.Mode.TEST);

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();
  private final PKCS12SignatureToken testSignatureToken = new PKCS12SignatureToken("testFiles/p12/signout.p12", "test".toCharArray());

  @Test
  public void signatureProfileLTTMTest() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    BDocSignature signature = (BDocSignature) SignatureBuilder
        .aSignature(container)
        .withSignatureToken(testSignatureToken)
        .withSignatureProfile(SignatureProfile.LT_TM).invokeSigning();
    container.addSignature(signature);

    assertEquals(signature.getSigningTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void signatureProfileLTTest() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    BDocSignature signature = (BDocSignature) SignatureBuilder
        .aSignature(container).withSignatureToken(testSignatureToken)
        .withSignatureProfile(SignatureProfile.LT).invokeSigning();
    container.addSignature(signature);

    assertEquals(signature.getSigningTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void signatureProfileLTATest() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    BDocSignature signature = (BDocSignature) SignatureBuilder
        .aSignature(container)
        .withSignatureToken(testSignatureToken)
        .withSignatureProfile(SignatureProfile.LTA).invokeSigning();
    container.addSignature(signature);

    assertEquals(signature.getSigningTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void signatureProfileB_BESTest() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    BDocSignature signature = (BDocSignature) SignatureBuilder
        .aSignature(container)
        .withSignatureToken(testSignatureToken)
        .withSignatureProfile(SignatureProfile.B_BES).invokeSigning();
    container.addSignature(signature);

    assertEquals(signature.getSigningTime(), signature.getClaimedSigningTime());
  }

  @Test
  public void signatureProfileB_EPESTest() throws Exception {
    Container container = TestDataBuilder.createContainerWithFile(testFolder);
    BDocSignature signature = (BDocSignature) SignatureBuilder
        .aSignature(container)
        .withSignatureToken(testSignatureToken)
        .withSignatureProfile(SignatureProfile.B_EPES).invokeSigning();
    container.addSignature(signature);

    assertEquals(signature.getSigningTime(), signature.getClaimedSigningTime());
  }


}
