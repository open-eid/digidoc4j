package org.digidoc4j.impl;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.Policy;
import org.apache.commons.lang3.SerializationUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SignatureFinalizerTest extends AbstractTest {

  private static final List<Integer> FILE_SIZES_IN_KILOBYTES = Arrays.asList(1, 100, 10000);
  private static final int DATA_TO_SIGN_DIGEST_EXPECTED_CEILING_SIZE = 1000;
  private static final int SIGNATURE_SIZE = 256;

  @Test
  public void finalizeSignature_emptyBDOCContainer_dataFilesFromPath() {
    for (int fileSize : FILE_SIZES_IN_KILOBYTES) {
      Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC).build();
      container.addDataFile("src/test/resources/testFiles/helper-files/sized-files/" + fileSize + "KB.txt", "text/plain");
      Signature signature = finalizeAndValidateSignature(container, 0);
//      assertTimemarkSignature(signature);
      container.addSignature(signature);
      assertTrue(container.validate().isValid());
    }
  }

  @Test
  public void finalizeSignature_emptyASICEContainer_dataFilesFromPath() {
    for (int fileSize : FILE_SIZES_IN_KILOBYTES) {
      Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICE).build();
      container.addDataFile("src/test/resources/testFiles/helper-files/sized-files/" + fileSize + "KB.txt", "text/plain");
      Signature signature = finalizeAndValidateSignature(container, 0);
      assertTimestampSignature(signature);
      container.addSignature(signature);
      assertTrue(container.validate().isValid());
    }
  }

  @Test
  public void finalizeSignature_emptyASICSContainer_dataFilesFromPath() {
    for (int fileSize : FILE_SIZES_IN_KILOBYTES) {
      Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).build();
      container.addDataFile("src/test/resources/testFiles/helper-files/sized-files/" + fileSize + "KB.txt", "text/plain");
      Signature signature = finalizeAndValidateSignature(container, 0);
      assertTimestampSignature(signature);
      assertTrue(container.validate().isValid());
    }
  }

  @Test
  public void finalizeSignature_emptyBDOCContainer_dataFilesAsStreams() throws FileNotFoundException {
    for (int fileSize : FILE_SIZES_IN_KILOBYTES) {
      Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC).build();
      String fileName = fileSize + "KB.txt";
      container.addDataFile(new FileInputStream("src/test/resources/testFiles/helper-files/sized-files/" + fileName), fileName, "text/plain");
      Signature signature = finalizeAndValidateSignature(container, fileSize * 1000);
//      assertTimemarkSignature(signature);
      container.addSignature(signature);
      assertTrue(container.validate().isValid());
    }
  }

  @Test
  public void finalizeSignature_emptyASICEContainer_dataFilesAsStreams() throws FileNotFoundException {
    for (int fileSize : FILE_SIZES_IN_KILOBYTES) {
      Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICE).build();
      String fileName = fileSize + "KB.txt";
      container.addDataFile(new FileInputStream("src/test/resources/testFiles/helper-files/sized-files/" + fileName), fileName, "text/plain");
      Signature signature = finalizeAndValidateSignature(container, fileSize * 1000);
      assertTimestampSignature(signature);
      container.addSignature(signature);
      assertTrue(container.validate().isValid());
    }
  }

  @Test
  public void finalizeSignature_emptyASICSContainer_dataFilesAsStreams() throws FileNotFoundException {
    for (int fileSize : FILE_SIZES_IN_KILOBYTES) {
      Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).build();
      String fileName = fileSize + "KB.txt";
      container.addDataFile(new FileInputStream("src/test/resources/testFiles/helper-files/sized-files/" + fileName), fileName, "text/plain");
      Signature signature = finalizeAndValidateSignature(container, fileSize * 1000);
      assertTimestampSignature(signature);
      assertTrue(container.validate().isValid());
    }
  }

  @Test
  public void finalizeSignature_emptyBDOCContainer_multipleDataFilesFromStream() throws FileNotFoundException {
    int dataFile1Size = 100;
    int dataFile2Size = 10000;
    String dataFile1Name = dataFile1Size + "KB.txt";
    String dataFile2Name = dataFile2Size + "KB.txt";
    Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC).build();
    container.addDataFile(new FileInputStream("src/test/resources/testFiles/helper-files/sized-files/" + dataFile1Size + "KB.txt"), dataFile1Name, "text/plain");
    container.addDataFile(new FileInputStream("src/test/resources/testFiles/helper-files/sized-files/" + dataFile2Size + "KB.txt"), dataFile2Name, "text/plain");
    Signature signature = finalizeAndValidateSignature(container, (dataFile1Size * 1000) + (dataFile2Size * 1000));
//    assertTimemarkSignature(signature);
    container.addSignature(signature);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void finalizeSignature_notEmptyContainerFromPath() {
    List<Container> containers = Arrays.asList(
            ContainerBuilder.aContainer().fromExistingFile("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc").build(),
            ContainerBuilder.aContainer().fromExistingFile("src/test/resources/testFiles/valid-containers/bdoc-tm-1000-signatures.bdoc").build(),
            ContainerBuilder.aContainer().fromExistingFile("src/test/resources/testFiles/valid-containers/valid-asice.asice").build(),
            ContainerBuilder.aContainer().fromExistingFile("src/test/resources/testFiles/valid-containers/asice-1000-signatures.asice").build(),
            ContainerBuilder.aContainer().fromExistingFile("src/test/resources/testFiles/valid-containers/asics-1-signature.asics").build()
    );

    for (Container container : containers) {
      Signature signature = finalizeAndValidateSignature(container, 40000);
      if (!container.getType().equalsIgnoreCase(Container.DocumentType.ASICS.name())) {
        container.addSignature(signature);
      }
    }
  }

  @Test
  public void finalizeSignature_notEmptyContainerFromStream() throws FileNotFoundException {
    List<Container> containers = Arrays.asList(
            ContainerBuilder.aContainer().fromStream(new FileInputStream("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc")).build(),
            ContainerBuilder.aContainer().fromStream(new FileInputStream("src/test/resources/testFiles/valid-containers/bdoc-tm-1000-signatures.bdoc")).build(),
            ContainerBuilder.aContainer().fromStream(new FileInputStream("src/test/resources/testFiles/valid-containers/valid-asice.asice")).build(),
            ContainerBuilder.aContainer().fromStream(new FileInputStream("src/test/resources/testFiles/valid-containers/asice-1000-signatures.asice")).build(),
            ContainerBuilder.aContainer().fromStream(new FileInputStream("src/test/resources/testFiles/valid-containers/asics-1-signature.asics")).build()
    );

    for (Container container: containers) {
      Signature signature = finalizeAndValidateSignature(container, 40000);
      if (!container.getType().equalsIgnoreCase(Container.DocumentType.ASICS.name())) {
        container.addSignature(signature);
      }
    }
  }

  @Test
  public void customSignaturePolicyForBdoc() {
    Policy customPolicy = new Policy();
    customPolicy.setId("SOME-ID");
    customPolicy.setSpuri("spuri");
    customPolicy.setQualifier("qualifier");
    customPolicy.setDigestValue("some".getBytes(StandardCharsets.UTF_8));
    customPolicy.setDigestAlgorithm(DigestAlgorithm.SHA512);

    Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC).build();
    container.addDataFile("src/test/resources/testFiles/helper-files/sized-files/1KB.txt", "text/plain");

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
        .withSigningCertificate(pkcs12SignatureToken.getCertificate())
        .withSignatureProfile(SignatureProfile.LT_TM)
        .withOwnSignaturePolicy(customPolicy)
        .buildDataToSign();

    assertEquals(customPolicy, dataToSign.getSignatureParameters().getPolicy());
    byte[] signatureValue = pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());
    Signature signature = dataToSign.finalize(signatureValue);
// TODO:    assertTimemarkSignature(signature);
    ValidationResult validationResult = signature.validateSignature();
    assertFalse(validationResult.isValid());
    assertEquals(1, validationResult.getWarnings().size());
    assertEquals("The signature/seal is an INDETERMINATE AdES!", validationResult.getWarnings().get(0).getMessage());
    assertEquals(1, validationResult.getErrors().size());
    assertEquals("The result of the LTV validation process is not acceptable to continue the process!", validationResult.getErrors().get(0).getMessage());
  }

  private Signature finalizeAndValidateSignature(Container container, int dataToSignAdditionalWeightInBytes) {
    DataToSign dataToSign = SignatureBuilder.aSignature(container)
        .withSigningCertificate(pkcs12SignatureToken.getCertificate())
        .buildDataToSign();

    byte[] dataToSignSerialized = SerializationUtils.serialize(dataToSign);
    assertTrue(dataToSignAdditionalWeightInBytes + 20000 > dataToSignSerialized.length);
    assertTrue(DATA_TO_SIGN_DIGEST_EXPECTED_CEILING_SIZE * container.getDataFiles().size() > dataToSign.getDataToSign().length);

    DataToSign dataToSignDeserialized = SerializationUtils.deserialize(dataToSignSerialized);
    byte[] signatureValue = pkcs12SignatureToken.sign(dataToSignDeserialized.getDigestAlgorithm(), dataToSignDeserialized.getDataToSign());
    assertEquals(SIGNATURE_SIZE, signatureValue.length);

    Signature signature = dataToSignDeserialized.finalize(signatureValue);
    assertTrue(signature.validateSignature().isValid());
    assertTrue(signature.validate().isEmpty());
    return signature;
  }
}
