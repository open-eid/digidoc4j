/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.testutils;

import static org.digidoc4j.testutils.TestSigningHelper.getSigningCert;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.DataToSign;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.junit.rules.TemporaryFolder;

public class TestDataBuilder {

  public static Container createContainerWithFile(TemporaryFolder testFolder) throws IOException {
    ContainerBuilder builder = ContainerBuilder.aContainer();
    Container container = populateContainerBuilderWithFile(builder, testFolder);
    return container;
  }

  public static Container createContainerWithFile(TemporaryFolder testFolder, String containerType) throws IOException {
    ContainerBuilder builder = ContainerBuilder.aContainer(containerType);
    Container container = populateContainerBuilderWithFile(builder, testFolder);
    return container;
  }

  public static Signature signContainer(Container container) {
    DataToSign dataToSign = buildDataToSign(container);
    return makeSignature(container, dataToSign);
  }

  public static Signature signContainer(Container container, DigestAlgorithm digestAlgorithm) {
    DataToSign dataToSign = prepareDataToSign(container).
        withSignatureDigestAlgorithm(digestAlgorithm).
        buildDataToSign();
    return makeSignature(container, dataToSign);
  }

  public static Signature makeSignature(Container container, DataToSign dataToSign) {
    byte[] signatureValue = TestSigningHelper.sign(dataToSign.getDigestToSign(), dataToSign.getDigestAlgorithm());
    assertNotNull(signatureValue);
    assertTrue(signatureValue.length > 1);

    Signature signature = dataToSign.finalize(signatureValue);
    container.addSignature(signature);
    return signature;
  }

  public static DataToSign buildDataToSign(Container container) {
    SignatureBuilder builder = prepareDataToSign(container);
    return builder.buildDataToSign();
  }

  public static DataToSign buildDataToSign(Container container, String signatureId) {
    SignatureBuilder builder = prepareDataToSign(container);
    builder.withSignatureId(signatureId);
    return builder.buildDataToSign();
  }

  private static Container populateContainerBuilderWithFile(ContainerBuilder builder, TemporaryFolder testFolder) throws IOException {
    File testFile = testFolder.newFile("testFile.txt");
    FileUtils.writeStringToFile(testFile, "Banana Pancakes");
    Container container = builder.
        withConfiguration(new Configuration(Configuration.Mode.TEST)).
        withDataFile(testFile.getPath(), "text/plain")
        .build();
    return container;
  }

  private static SignatureBuilder prepareDataToSign(Container container) {
    return SignatureBuilder.
        aSignature(container).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT_TM).
        withSigningCertificate(getSigningCert());
  }
}
