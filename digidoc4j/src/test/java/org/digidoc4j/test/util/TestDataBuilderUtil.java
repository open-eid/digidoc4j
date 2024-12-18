/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.test.util;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.junit.Assert;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class TestDataBuilderUtil {

  public static Container createContainerWithFile(TemporaryFolder folder) throws IOException {
    return TestDataBuilderUtil.createContainerWithFile(folder, Container.DocumentType.BDOC, Configuration.Mode.TEST);
  }

  public static Container createContainerWithFile(TemporaryFolder folder, String containerType) throws IOException {
    return TestDataBuilderUtil.createContainerWithFile(folder, containerType, Configuration.Mode.TEST);
  }

  public static Container createContainerWithFile(TemporaryFolder folder, Container.DocumentType containerType) throws IOException {
    return TestDataBuilderUtil.createContainerWithFile(folder, containerType, Configuration.Mode.TEST);
  }

  public static Container createContainerWithFile(TemporaryFolder folder, String containerType, Configuration.Mode mode) throws IOException {
    return TestDataBuilderUtil.createContainerWithFile(folder, containerType, Configuration.of(mode));
  }

  public static Container createContainerWithFile(TemporaryFolder folder, String containerType, Configuration configuration) throws IOException {
    return TestDataBuilderUtil.populateContainerBuilderWithFile(ContainerBuilder.aContainer(containerType), folder, configuration);
  }

  public static Container createContainerWithFile(TemporaryFolder folder, Container.DocumentType type, Configuration.Mode mode) throws IOException {
    return TestDataBuilderUtil.createContainerWithFile(folder, type, Configuration.of(mode));
  }

  public static Container createContainerWithFile(TemporaryFolder folder, Container.DocumentType type, Configuration configuration) throws IOException {
    return TestDataBuilderUtil.populateContainerBuilderWithFile(ContainerBuilder.aContainer(type), folder, configuration);
  }

  public static Container createContainerWithFile(String dataFilePath) {
    return TestDataBuilderUtil.createContainerWithFile(dataFilePath, "text/plain");
  }

  public static Container createContainerWithFile(String dataFilePath, String mimeType) {
    return ContainerBuilder.aContainer(Container.DocumentType.BDOC).withConfiguration(new Configuration(Configuration.Mode.TEST)).
        withDataFile(dataFilePath, mimeType).build();
  }

  public static Signature signContainer(Container container) {
    return TestDataBuilderUtil.makeSignature(container, TestDataBuilderUtil.buildDataToSign(container));
  }

  public static Signature signContainer(Container container, DigestAlgorithm digestAlgorithm) {
    return TestDataBuilderUtil.makeSignature(container, prepareDataToSign(container).withSignatureDigestAlgorithm(digestAlgorithm).
        buildDataToSign());
  }

  public static Signature signContainer(Container container, SignatureProfile signatureProfile) {
    return TestDataBuilderUtil.makeSignature(container, TestDataBuilderUtil.prepareDataToSign(container).withSignatureProfile(signatureProfile).buildDataToSign());
  }

  public static Signature makeSignature(Container container, DataToSign dataToSign) {
    byte[] signatureValue = TestSigningUtil.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());
    Assert.assertNotNull(signatureValue);
    Assert.assertTrue(signatureValue.length > 1);
    Signature signature = dataToSign.finalize(signatureValue);
    container.addSignature(signature);
    return signature;
  }

  public static DataToSign buildDataToSign(Container container) {
    return TestDataBuilderUtil.prepareDataToSign(container).buildDataToSign();
  }

  public static DataToSign buildDataToSign(Container container, String signatureId) {
    SignatureBuilder builder = TestDataBuilderUtil.prepareDataToSign(container);
    builder.withSignatureId(signatureId);
    return builder.buildDataToSign();
  }

  public static Container open(String path, Configuration configuration) {
    return ContainerBuilder.aContainer().fromExistingFile(path).withConfiguration(configuration).build();
  }

  public static Container open(String path) {
    return ContainerBuilder.aContainer().fromExistingFile(path).build();
  }

  public static Container open(DataFile dataFile, Configuration configuration) {
    try (InputStream in = dataFile.getStream()) {
      return ContainerBuilder.aContainer().fromStream(in).withConfiguration(configuration).build();
    } catch (IOException e) {
      throw new IllegalStateException("Failed to open stream from: " + dataFile, e);
    }
  }

  public static Container open(DataFile dataFile) {
    try (InputStream in = dataFile.getStream()) {
      return ContainerBuilder.aContainer().fromStream(in).build();
    } catch (IOException e) {
      throw new IllegalStateException("Failed to open stream from: " + dataFile, e);
    }
  }

  private static Container populateContainerBuilderWithFile(ContainerBuilder builder, TemporaryFolder testFolder, Configuration configuration) throws IOException {
    File testFile = TestDataBuilderUtil.createTestFile(testFolder);
    return builder.withConfiguration(configuration).withDataFile(testFile.getPath(), "text/plain").build();
  }

  private static SignatureBuilder prepareDataToSign(Container container) {
    return SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT).withSigningCertificate(TestSigningUtil.getSigningCertificate());
  }

  public static File createTestFile(TemporaryFolder testFolder) throws IOException {
    File testFile = testFolder.newFile();
    FileUtils.writeStringToFile(testFile, "Banana Pancakes", StandardCharsets.UTF_8);
    return testFile;
  }

}
