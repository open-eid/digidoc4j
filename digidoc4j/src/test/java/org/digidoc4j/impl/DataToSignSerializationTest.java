/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import org.apache.commons.lang3.SerializationUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DetachedXadesSignatureBuilder;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.asics.AsicSSignature;
import org.junit.Ignore;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

// These tests might take long and are not necessary to be run in every build.
// They fit more into performance tests category, so at the moment they will be run with them.
@Ignore
public class DataToSignSerializationTest extends AbstractTest {

  private static final List<Integer> FILE_SIZES_IN_KILOBYTES = Arrays.asList(1, 100, 10000);
  private static final int DATA_TO_SIGN_DIGEST_EXPECTED_CEILING_SIZE = 1000;
  private static final int SIGNATURE_SIZE = 256;

  @Test
  public void finalizeSignature_emptyBDOCContainer_dataFilesFromPath() {
    for (int fileSize : FILE_SIZES_IN_KILOBYTES) {
      Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC).build();
      container.addDataFile("src/test/resources/testFiles/helper-files/sized-files/" + fileSize + "KB.txt", "text/plain");
      Signature signature = finalizeAndValidateContainerSignature(container, 0);
      assertTimestampSignature(signature);
      container.addSignature(signature);
      assertTrue(container.validate().isValid());
    }
  }

  @Test
  public void finalizeSignature_emptyASICEContainer_dataFilesFromPath() {
    for (int fileSize : FILE_SIZES_IN_KILOBYTES) {
      Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICE).build();
      container.addDataFile("src/test/resources/testFiles/helper-files/sized-files/" + fileSize + "KB.txt", "text/plain");
      Signature signature = finalizeAndValidateContainerSignature(container, 0);
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
      Signature signature = finalizeAndValidateContainerSignature(container, 0);
      assertThat(signature, instanceOf(AsicSSignature.class));
      assertThat(signature.getProfile(), sameInstance(SignatureProfile.LT));
      assertTrue(container.validate().isValid());
    }
  }

  @Test
  public void finalizeSignature_emptyBDOCContainer_dataFilesAsStreams() throws FileNotFoundException {
    for (int fileSize : FILE_SIZES_IN_KILOBYTES) {
      Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC).build();
      String fileName = fileSize + "KB.txt";
      container.addDataFile(new FileInputStream("src/test/resources/testFiles/helper-files/sized-files/" + fileName), fileName, "text/plain");
      Signature signature = finalizeAndValidateContainerSignature(container, fileSize * 1000);
      assertTimestampSignature(signature);
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
      Signature signature = finalizeAndValidateContainerSignature(container, fileSize * 1000);
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
      Signature signature = finalizeAndValidateContainerSignature(container, fileSize * 1000);
      assertThat(signature, instanceOf(AsicSSignature.class));
      assertThat(signature.getProfile(), sameInstance(SignatureProfile.LT));
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
    Signature signature = finalizeAndValidateContainerSignature(container, (dataFile1Size * 1000) + (dataFile2Size * 1000));
    assertTimestampSignature(signature);
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
      Signature signature = finalizeAndValidateContainerSignature(container, 80000);
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
      Signature signature = finalizeAndValidateContainerSignature(container, 80000);
      if (!container.getType().equalsIgnoreCase(Container.DocumentType.ASICS.name())) {
        container.addSignature(signature);
      }
    }
  }

  @Test
  public void finalizeDetachedTimestampSignature_dataFileFromStream() throws FileNotFoundException {
    for (int fileSize : FILE_SIZES_IN_KILOBYTES) {
      String fileName = fileSize + "KB.txt";
      DataFile dataFile = new DataFile(new FileInputStream("src/test/resources/testFiles/helper-files/sized-files/" + fileName), fileName, "text/plain");
      Signature signature = finalizeAndValidateDetachedSignature(dataFile, SignatureProfile.LT, fileSize * 1000);
      assertTimestampSignature(signature);
    }
  }

  private Signature finalizeAndValidateContainerSignature(Container container, int dataToSignAdditionalWeightInBytes) {
    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .buildDataToSign();

    return finalizeAndValidateSignature(dataToSign, container.getDataFiles().size(), dataToSignAdditionalWeightInBytes);
  }

  private Signature finalizeAndValidateDetachedSignature(DataFile dataFile, SignatureProfile signatureProfile, int dataToSignAdditionalWeightInBytes) {
    DataToSign dataToSign = DetachedXadesSignatureBuilder.withConfiguration(Configuration.of(Configuration.Mode.TEST))
         .withDataFile(dataFile)
         .withSignatureProfile(signatureProfile)
         .withSigningCertificate(pkcs12SignatureToken.getCertificate())
         .buildDataToSign();

    return finalizeAndValidateSignature(dataToSign, 1, dataToSignAdditionalWeightInBytes);
  }

  /*
    Data is serialized and the outcome size is asserted against APPROXIMATE highest value.
    This test monitors possible DataToSign object size increases that would result in less effective serialization process.
    If these assertions start to fail one must consider if the object increase is deliberate and increase expected max size values.
   */
  private Signature finalizeAndValidateSignature(DataToSign dataToSign, int dataFilesCount, int dataToSignAdditionalWeightInBytes) {
    byte[] dataToSignSerialized = SerializationUtils.serialize(dataToSign);

    assertThat(dataToSignSerialized.length, lessThan(dataToSignAdditionalWeightInBytes + 55000));
    assertThat(dataToSign.getDataToSign().length, lessThan(DATA_TO_SIGN_DIGEST_EXPECTED_CEILING_SIZE * dataFilesCount));

    DataToSign dataToSignDeserialized = SerializationUtils.deserialize(dataToSignSerialized);
    byte[] signatureValue = pkcs12SignatureToken.sign(dataToSignDeserialized.getDigestAlgorithm(), dataToSignDeserialized.getDataToSign());
    assertEquals(SIGNATURE_SIZE, signatureValue.length);

    Instant trustedSigningTimeLowerBound = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    Signature signature = dataToSignDeserialized.finalize(signatureValue);
    assertTimeInBounds(signature.getTrustedSigningTime(), trustedSigningTimeLowerBound, Duration.ofSeconds(5));

    assertValidSignature(signature);
    return signature;
  }

}
