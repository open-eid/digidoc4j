/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.ddoc.utils.ConfigManager;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidDataFileException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.asice.AsicEContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.test.CustomConfiguration;
import org.digidoc4j.test.CustomContainer;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.digidoc4j.utils.Helper;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.zip.ZipFile;

import static org.digidoc4j.Container.DocumentType.ASICE;
import static org.digidoc4j.Container.DocumentType.ASICS;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.digidoc4j.Container.DocumentType.DDOC;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ContainerBuilderTest extends AbstractTest {

  @Test
  public void buildEmptyContainer() throws Exception {
    ContainerBuilder builder = ContainerBuilder.aContainer();
    Container container = builder.build();
    assertEquals("ASICE", container.getType());
    assertTrue(container.getDataFiles().isEmpty());
    assertTrue(container.getSignatures().isEmpty());
  }

  @Test(expected = NotSupportedException.class)
  public void buildEmptyDDocContainer() throws Exception {
    ContainerBuilder.aContainer(DDOC).build();
  }

  @Test
  public void buildBDocContainer() throws Exception {
    configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setTspSource("test-value");
    Container container = ContainerBuilder.aContainer(BDOC).withConfiguration(configuration).build();
    BDocContainer bDocContainer = (BDocContainer) container;
    assertEquals("BDOC", container.getType());
    assertEquals("test-value", bDocContainer.getConfiguration().getTspSource());
  }

  @Test
  public void buildBDocContainerWithDataFiles() throws Exception {
    File testFile1 = createTemporaryFileBy("testFile.txt", "TEST");
    File testFile2 = createTemporaryFileBy("testFile2.txt", "TEST");
    LargeDataFile largeDataFile = new LargeDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "largeStreamFile.txt", "text/plain");
    Container container = ContainerBuilder.aContainer().withDataFile(testFile1.getPath(), "text/plain").
        withDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "streamFile.txt", "text/plain").
        withDataFile(createTemporaryFileBy("ExampleFile.txt", "TEST"), "text/plain").
        withDataFile(new DataFile(testFile2.getPath(), "text/plain")).withDataFile(largeDataFile).build();
    assertEquals(5, container.getDataFiles().size());
    assertEquals("testFile.txt", container.getDataFiles().get(0).getName());
    assertEquals("streamFile.txt", container.getDataFiles().get(1).getName());
    assertEquals("ExampleFile.txt", container.getDataFiles().get(2).getName());
    assertEquals("testFile2.txt", container.getDataFiles().get(3).getName());
    assertEquals("largeStreamFile.txt", container.getDataFiles().get(4).getName());
  }

  @Test
  public void buildASiCSContainerWithSecondDataFile() {
    ContainerBuilder containerBuilder = ContainerBuilder.aContainer(ASICS)
            .withDataFile(new DataFile(new byte[] {0}, "file.name", "application/octet-stream"));
    DigiDoc4JException caughtException = assertThrows(
            DigiDoc4JException.class,
            () -> containerBuilder.withDataFile(new DataFile(new byte[] {0}, "file2.name", "application/octet-stream"))
    );
    assertEquals("Cannot add second file in case of ASiCS container", caughtException.getMessage());
  }

  @Test
  public void buildASiCSContainerWithSecondDataFileFromFile() {
    File testFile = createTemporaryFileBy("testFile.txt", "TEST");
    ContainerBuilder containerBuilder = ContainerBuilder.aContainer(ASICS)
            .withDataFile(new DataFile(new byte[] {0}, "file.name", "application/octet-stream"));
    DigiDoc4JException caughtException = assertThrows(
            DigiDoc4JException.class,
            () -> containerBuilder.withDataFile(testFile, "application/octet-stream")
    );
    assertEquals("Cannot add second file in case of ASiCS container", caughtException.getMessage());
  }

  @Test
  public void buildASiCSContainerWithSecondDataFileFromPath() {
    File testFile = createTemporaryFileBy("testFile.txt", "TEST");
    ContainerBuilder containerBuilder = ContainerBuilder.aContainer(ASICS)
            .withDataFile(new DataFile(new byte[] {0}, "file.name", "application/octet-stream"));
    DigiDoc4JException caughtException = assertThrows(
            DigiDoc4JException.class,
            () -> containerBuilder.withDataFile(testFile.getPath(), "application/octet-stream")
    );
    assertEquals("Cannot add second file in case of ASiCS container", caughtException.getMessage());
  }

  @Test
  public void buildASiCSContainerWithSecondDataFileFromInputStream() {
    ContainerBuilder containerBuilder = ContainerBuilder.aContainer(ASICS)
            .withDataFile(new DataFile(new byte[] {0}, "file.name", "application/octet-stream"));
    DigiDoc4JException caughtException = assertThrows(
            DigiDoc4JException.class,
            () -> containerBuilder.withDataFile(new ByteArrayInputStream(new byte[] {0}), "file.name", "application/octet-stream")
    );
    assertEquals("Cannot add second file in case of ASiCS container", caughtException.getMessage());
  }

  @Test(expected = InvalidDataFileException.class)
  public void buildContainer_withNullFilePath_shouldThrowException() throws Exception {
    ContainerBuilder.aContainer().withDataFile((String) null, "text/plain").build();
  }

  @Test
  public void withDatafile_whenIllegalCharactersInFileName_invalidDataFileExceptionIsThrown() {
    String illegalFileName = "00000705/a1b2c3d4-00000705-20250521.txt";
    String mimeType = "text/plain";
    byte[] fileContent = {1, 2, 3};

    ContainerBuilder containerBuilder = ContainerBuilder.aContainer();
    DataFile dataFile = new DataFile(
            new ByteArrayInputStream(fileContent),
            illegalFileName,
            mimeType
    );

    InvalidDataFileException exception = assertThrows(
            InvalidDataFileException.class,
            () -> containerBuilder.withDataFile(dataFile));

    String expectedMessage = String.format(
            "File name %s must not contain special characters like: %s",
            illegalFileName,
            Helper.FORBIDDEN_CHARACTERS
    );
    assertEquals(expectedMessage, exception.getMessage());
  }

  @Test(expected = InvalidDataFileException.class)
  public void buildContainer_withStreamDocAndNullFileName_shouldThrowException() throws Exception {
    ContainerBuilder.aContainer().withDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), null, "text/plain").
        build();
  }

  @Test(expected = InvalidDataFileException.class)
  public void buildContainer_withNullMimeType_shouldThrowException() throws Exception {
    ContainerBuilder.aContainer().withDataFile("testFile.txt", null).build();
  }

  @Test
  public void buildContainer_withInvalidMimeType_shouldSucceed() {
    Container container = ContainerBuilder.aContainer().
        withDataFile("src/test/resources/testFiles/helper-files/test.txt", "application\\rtf").build();
    assertTrue(container.validate().isValid());
  }

  @Test
  public void signAndValidateContainer() throws Exception {
    Container container = createNonEmptyContainer();
    TestDataBuilderUtil.signContainer(container);
    ContainerValidationResult result = container.validate();
    assertTrue(result.isValid());
    assertFalse(result.hasWarnings());
    assertTrue(result.getContainerErrors().isEmpty());
    assertTrue(result.isValid());
    assertTrue(StringUtils.containsIgnoreCase(result.getReport(), "<Indication>TOTAL_PASSED</Indication>"));
  }

  @Test
  public void saveContainerWithoutSignaturesToFile() throws Exception {
    File dataFile = TestDataBuilderUtil.createTestFile(testFolder);
    Container container = TestDataBuilderUtil.createContainerWithFile(dataFile.getPath());
    String filePath = testFolder.newFile("test-container.bdoc").getPath();
    File containerFile = container.saveAsFile(filePath);
    assertTrue(FileUtils.sizeOf(containerFile) > 0);
    try (ZipFile zip = new ZipFile(filePath)) {
      assertNotNull(zip.getEntry("mimetype"));
      assertNotNull(zip.getEntry("META-INF/manifest.xml"));
      assertNotNull(zip.getEntry(dataFile.getName()));
    }
  }

  @Test
  public void signAndSaveContainerToFile() throws Exception {
    Container container = createNonEmptyContainer();
    TestDataBuilderUtil.signContainer(container);
    String filePath = testFolder.newFile("test-container.bdoc").getPath();
    assertEquals(1, container.getSignatures().size());
    File file = container.saveAsFile(filePath);
    assertTrue(FileUtils.sizeOf(file) > 0);
    try (ZipFile zip = new ZipFile(filePath)) {
      assertNotNull(zip.getEntry("META-INF/signatures0.xml"));
    }
  }

  @Test
  public void signAndSaveContainerToStream() throws Exception {
    Container container = createNonEmptyContainer();
    createSignatureBy(container, pkcs12SignatureToken);
    try (InputStream stream = container.saveAsStream()) {
      byte[] bytes = IOUtils.toByteArray(stream);
      assertTrue(bytes.length > 10);
    }
  }

  @Test
  public void removeSignatureFromSignedContainer() throws Exception {
    Container container = TestDataBuilderUtil.createContainerWithFile(testFolder);
    Signature signature = TestDataBuilderUtil.signContainer(container);
    container.saveAsFile(getFileBy("bdoc"));
    container.removeSignature(signature);
    assertTrue(container.getSignatures().isEmpty());
  }

  @Test
  public void buildCustomContainerWithCustomImplementation() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").build();
    assertEquals("TEST-FORMAT", container.getType());
  }

  @Test
  public void overrideExistingBDocContainerImplementation() throws Exception {
    ContainerBuilder.setContainerImplementation("ASICE", CustomContainer.class);
    Container container = ContainerBuilder.aContainer().build();
    assertEquals("TEST-FORMAT", container.getType());
  }

  @Disabled
  @Test
  public void useExtendedBDocContainerImplementation() throws Exception {
    ContainerBuilder.setContainerImplementation("BDOC", BDocContainer.class);
    Container container = ContainerBuilder.
        aContainer("BDOC").
        build();
    assertEquals("BDOC-EXTENDED", container.getType());
  }

  @Test
  public void clearCustomContainerImplementations_shouldUseDefaultContainerImplementation() throws Exception {
    ContainerBuilder.setContainerImplementation("ASICE", AsicEContainer.class);
    ContainerBuilder.removeCustomContainerImplementations();
    Container container = ContainerBuilder.aContainer().build();
    assertEquals("ASICE", container.getType());
  }

  @Test
  public void createCustomContainerWithConfiguration() throws Exception {
    configuration = Configuration.of(Configuration.Mode.TEST);
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").
        withConfiguration(configuration).build();
    assertEquals("TEST-FORMAT", container.getType());
    assertSame(configuration, ((CustomContainer) container).getConfiguration());
  }

  @Test
  public void createCustomContainerWithCustomConfiguration() throws Exception {
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    CustomConfiguration configuration = new CustomConfiguration();
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").
        withConfiguration(configuration).build();
    assertEquals("TEST-FORMAT", container.getType());
    assertSame(configuration, ((CustomContainer) container).getConfiguration());
  }

  @Test
  public void openDefaultContainerFromFile() throws Exception {
    Container container = ContainerBuilder.aContainer().fromExistingFile(BDOC_WITH_TM_SIG).build();
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
  }

  @Test
  public void openDefaultContainerFromFileWithConfiguration() throws Exception {
    configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setTspSource("test-value");
    Container container = ContainerBuilder.aContainer().withConfiguration(configuration).
        fromExistingFile(BDOC_WITH_TM_SIG).build();
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
    assertEquals("test-value", ((BDocContainer) container).getConfiguration().getTspSource());
  }

  @Test
  public void openDDocContainerFromFile_whenUsingDefaultContainer() throws Exception {
    Container container = ContainerBuilder.aContainer().fromExistingFile(DDOC_TEST_FILE).build();
    TestAssert.assertContainerIsOpened(container, DDOC);
  }

  @Test
  public void openDDocContainerFromFile() throws Exception {
    Container container = ContainerBuilder.aContainer("DDOC").fromExistingFile(DDOC_TEST_FILE).build();
    TestAssert.assertContainerIsOpened(container, DDOC);
  }

  @Test
  public void openCustomContainerFromFile() throws Exception {
    File testFile = createTemporaryFileBy("testFile.txt", "TEST");
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").fromExistingFile(testFile.getPath()).build();
    assertEquals("TEST-FORMAT", container.getType());
    assertEquals(testFile.getPath(), ((CustomContainer) container).getOpenedFromFile());
  }

  @Test
  public void openCustomContainerFromFile_withConfiguration() throws Exception {
    configuration = Configuration.of(Configuration.Mode.TEST);
    File testFile = createTemporaryFileBy("testFile.txt", "TEST");
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").withConfiguration(configuration).
        fromExistingFile(testFile.getPath()).build();
    assertEquals("TEST-FORMAT", container.getType());
    assertEquals(testFile.getPath(), ((CustomContainer) container).getOpenedFromFile());
    assertSame(configuration, ((CustomContainer) container).getConfiguration());
  }

  @Test
  public void openCustomContainerFromFile_withCustomConfiguration() throws Exception {
    CustomConfiguration configuration = new CustomConfiguration(Configuration.Mode.TEST);
    File testFile = createTemporaryFileBy("testFile.txt", "TEST");
    ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
    Container container = ContainerBuilder.aContainer("TEST-FORMAT").withConfiguration(configuration).
        fromExistingFile(testFile.getPath()).build();
    assertEquals("TEST-FORMAT", container.getType());
    assertEquals(testFile.getPath(), ((CustomContainer) container).getOpenedFromFile());
    assertSame(configuration, ((CustomContainer) container).getConfiguration());
  }

  @Test
  public void openBDocContainerFromStream() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_TM_SIG))) {
      Container container = ContainerBuilder.aContainer().fromStream(stream).build();
      assertBDocContainer(container);
      assertSame(1, container.getSignatures().size());
      assertTimemarkSignature(container.getSignatures().get(0));
      TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
    }
  }

  @Test
  public void openBDocContainerWithTMAndTSSignaturesFromStream() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_TM_AND_TS_SIG))) {
      Container container = ContainerBuilder.aContainer().fromStream(stream).build();
      assertBDocContainer(container);
      assertSame(2, container.getSignatures().size());
      assertTimemarkSignature(container.getSignatures().get(0));
      assertLtSignature(container.getSignatures().get(1));
      TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
    }
  }

  @Test
  public void openBDocContainerFromStream_withConfiguration() throws Exception {
    configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setTspSource("test-value");
    InputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_TM_SIG));
    Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC).
        withConfiguration(configuration).
        fromStream(stream).build();
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
    assertBDocContainer(container);
    assertEquals("test-value", container.getConfiguration().getTspSource());
  }

  @Test
  public void openBDocContainerWithBEpesSignatureFromStream_withConfiguration() throws Exception {
    InputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_B_EPES_SIG));
    Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC)
        .withConfiguration(configuration)
        .fromStream(stream)
        .build();
    TestAssert.assertContainerIsOpened(container, Container.DocumentType.BDOC);
    assertBDocContainer(container);
    assertBEpesSignature(container.getSignatures().get(0));
  }

  @Test
  public void openBDocContainerWithSignaturesEvenWhenBuilderInputRequestsAsice() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(ASICE_WITH_TS_SIG))) {
      Container container = ContainerBuilder.aContainer(ASICE).fromStream(stream).build();
      assertAsicEContainer(container);
      assertSame(1, container.getSignatures().size());
      assertLtSignature(container.getSignatures().get(0));
    }
  }

  @Test
  public void openBDocContainerWithNoSignaturesFromFile_requiringBDoc_returnedBDoc() {
    Container container = ContainerBuilder.aContainer(BDOC).fromExistingFile(BDOC_WITH_NO_SIG).build();
    assertBDocContainer(container);
    assertEquals(0, container.getSignatures().size());
  }

  @Test
  public void openBDocContainerWithNoSignaturesFromStream_requiringBDoc_returnedBDoc() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_NO_SIG))) {
      Container container = ContainerBuilder.aContainer(BDOC).fromStream(stream).build();
      assertBDocContainer(container);
      assertEquals(0, container.getSignatures().size());
    }
  }

  @Test
  public void openBDocContainerWithNoSignaturesFromFile_requiringAsicE_returnedAsicE() {
    Container container = ContainerBuilder.aContainer(ASICE).fromExistingFile(BDOC_WITH_NO_SIG).build();
    assertAsicEContainer(container);
    assertEquals(0, container.getSignatures().size());
  }

  @Test
  public void openBDocContainerWithNoSignaturesFromStream_requiringAsicE_returnedAsicE() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_NO_SIG))) {
      Container container = ContainerBuilder.aContainer(ASICE).fromStream(stream).build();
      assertAsicEContainer(container);
      assertEquals(0, container.getSignatures().size());
    }
  }

  @Test
  public void openBDocContainerWithNoSignaturesFromFile_requiringAsicS_returnedAsicE() {
    Container container = ContainerBuilder.aContainer(ASICS).fromExistingFile(BDOC_WITH_NO_SIG).build();
    assertAsicEContainer(container);
    assertEquals(0, container.getSignatures().size());
  }

  @Test
  public void openBDocContainerWithNoSignaturesFromStream_requiringAsicS_returnedAsicE() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(BDOC_WITH_NO_SIG))) {
      Container container = ContainerBuilder.aContainer(ASICS).fromStream(stream).build();
      assertAsicEContainer(container);
      assertEquals(0, container.getSignatures().size());
    }
  }

  @Test
  public void openAsicEContainerFromStream() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(ASICE_WITH_TS_SIG))) {
      Container container = ContainerBuilder.aContainer().fromStream(stream).build();
      assertAsicEContainer(container);
      assertSame(1, container.getSignatures().size());
      assertLtSignature(container.getSignatures().get(0));
      TestAssert.assertContainerIsOpened(container, ASICE);
    }
  }

  @Test
  public void openAsicEContainerWithNoSignaturesFromFile_requiringBDoc_returnedBDoc() {
    Container container = ContainerBuilder.aContainer(BDOC).fromExistingFile(ASICE_WITH_NO_SIG).build();
    assertBDocContainer(container);
    assertSame(0, container.getSignatures().size());
  }

  @Test
  public void openAsicEContainerWithNoSignaturesFromStream_requiringBDoc_returnedBDoc() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(ASICE_WITH_NO_SIG))) {
      Container container = ContainerBuilder.aContainer(BDOC).fromStream(stream).build();
      assertBDocContainer(container);
      assertSame(0, container.getSignatures().size());
    }
  }

  @Test
  public void openAsicEContainerWithNoSignaturesFromFile_requiringAsicE_returnedAsicE() {
    Container container = ContainerBuilder.aContainer(ASICE).fromExistingFile(ASICE_WITH_NO_SIG).build();
    assertAsicEContainer(container);
    assertSame(0, container.getSignatures().size());
  }

  @Test
  public void openAsicEContainerWithNoSignaturesFromStream_requiringAsicE_returnedAsicE() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(ASICE_WITH_NO_SIG))) {
      Container container = ContainerBuilder.aContainer(ASICE).fromStream(stream).build();
      assertAsicEContainer(container);
      assertSame(0, container.getSignatures().size());
    }
  }

  @Test
  public void openAsicEContainerWithNoSignaturesFromFile_requiringAsicS_returnedAsicE() {
    Container container = ContainerBuilder.aContainer(ASICS).fromExistingFile(ASICE_WITH_NO_SIG).build();
    assertAsicEContainer(container);
    assertSame(0, container.getSignatures().size());
  }

  @Test
  public void openAsicEContainerWithNoSignaturesFromStream_requiringAsicS_returnedAsicE() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(ASICE_WITH_NO_SIG))) {
      Container container = ContainerBuilder.aContainer(ASICS).fromStream(stream).build();
      assertAsicEContainer(container);
      assertSame(0, container.getSignatures().size());
    }
  }

  @Test
  public void openAsiceContainerWithSignaturesEvenWhenBuilderInputRequestsBDoc() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(ASICE_WITH_TS_SIG))) {
      Container container = ContainerBuilder.aContainer(BDOC).fromStream(stream).build();
      assertAsicEContainer(container);
      assertSame(1, container.getSignatures().size());
      assertLtSignature(container.getSignatures().get(0));
    }
  }

  @Test
  public void openAsiceContainerWithBDocFileExtension() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(ASICE_WITH_TS_SIG_BUT_BDOC_EXTENSION))) {
      Container container = ContainerBuilder.aContainer().fromStream(stream).build();
      assertAsicEContainer(container);
      assertSame(1, container.getSignatures().size());
      assertTimestampSignature(container.getSignatures().get(0));
    }
  }

  @Test
  public void openAsicSContainerWithNoSignaturesFromFile_requiringBDoc_returnedAsicS() {
    Container container = ContainerBuilder.aContainer(BDOC).fromExistingFile(ASICS_WITH_NO_SIG).build();
    assertAsicSContainer(container);
    assertSame(0, container.getSignatures().size());
  }

  @Test
  public void openAsicSContainerWithNoSignaturesFromStream_requiringBDoc_returnedAsicS() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(ASICS_WITH_NO_SIG))) {
      Container container = ContainerBuilder.aContainer(BDOC).fromStream(stream).build();
      assertAsicSContainer(container);
      assertSame(0, container.getSignatures().size());
    }
  }

  @Test
  public void openAsicSContainerWithNoSignaturesFromFile_requiringAsicE_returnedAsicS() {
    Container container = ContainerBuilder.aContainer(ASICE).fromExistingFile(ASICS_WITH_NO_SIG).build();
    assertAsicSContainer(container);
    assertSame(0, container.getSignatures().size());
  }

  @Test
  public void openAsicSContainerWithNoSignaturesFromStream_requiringAsicE_returnedAsicS() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(ASICS_WITH_NO_SIG))) {
      Container container = ContainerBuilder.aContainer(ASICE).fromStream(stream).build();
      assertAsicSContainer(container);
      assertSame(0, container.getSignatures().size());
    }
  }

  @Test
  public void openAsicSContainerWithNoSignaturesFromFile_requiringAsicS_returnedAsicS() {
    Container container = ContainerBuilder.aContainer(ASICS).fromExistingFile(ASICS_WITH_NO_SIG).build();
    assertAsicSContainer(container);
    assertSame(0, container.getSignatures().size());
  }

  @Test
  public void openAsicSContainerWithNoSignaturesFromStream_requiringAsicS_returnedAsicS() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(new File(ASICS_WITH_NO_SIG))) {
      Container container = ContainerBuilder.aContainer(ASICS).fromStream(stream).build();
      assertAsicSContainer(container);
      assertSame(0, container.getSignatures().size());
    }
  }

  @Test
  public void openDDocContainerFromStream() throws Exception {
    InputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE));
    Container container = ContainerBuilder.aContainer().fromStream(stream).build();
    TestAssert.assertContainerIsOpened(container, DDOC);
  }

  @Test
  public void openDDocContainerFromStream_withConfiguration() throws Exception {
    configuration = Configuration.of(Configuration.Mode.TEST);
    try (InputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE))) {
      Container container = ContainerBuilder.aContainer(DDOC).withConfiguration(configuration).
          fromStream(stream).build();
      TestAssert.assertContainerIsOpened(container, DDOC);
      assertSame(configuration, ((DDocContainer) container).getDDoc4JFacade().getConfiguration());
    }
  }

  @Test
  public void openDefaultContainerFromStream_withDDOC() throws Exception {
    InputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE));
    Container container = ContainerBuilder.aContainer().withConfiguration(Configuration.of(Configuration.Mode.TEST)).
        fromStream(stream).build();
    TestAssert.assertContainerIsOpened(container, DDOC);
  }

  @Test
  public void openCustomContainerFromStream() throws Exception {
    try (InputStream stream = FileUtils.openInputStream(createTemporaryFileBy("testFile.txt", "TEST"))) {
      ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
      Container container = ContainerBuilder.aContainer("TEST-FORMAT").fromStream(stream).build();
      assertEquals("TEST-FORMAT", container.getType());
      assertSame(stream, ((CustomContainer) container).getOpenedFromStream());
    }
  }

  @Test
  public void openCustomContainerFromStream_withConfiguration() throws Exception {
    configuration = Configuration.of(Configuration.Mode.TEST);
    try (InputStream stream = FileUtils.openInputStream(createTemporaryFileBy("testFile.txt", "TEST"))) {
      ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
      Container container = ContainerBuilder.aContainer("TEST-FORMAT").withConfiguration(configuration).
              fromStream(stream).build();
      assertEquals("TEST-FORMAT", container.getType());
      assertSame(stream, ((CustomContainer) container).getOpenedFromStream());
      assertSame(configuration, ((CustomContainer) container).getConfiguration());
    }
  }

  @Test
  public void openCustomContainerFromStream_withCustomConfiguration() throws Exception {
    configuration = new CustomConfiguration();
    try (InputStream stream = FileUtils.openInputStream(createTemporaryFileBy("testFile.txt", "TEST"))) {
      ContainerBuilder.setContainerImplementation("TEST-FORMAT", CustomContainer.class);
      Container container = ContainerBuilder.aContainer("TEST-FORMAT").withConfiguration(configuration).
              fromStream(stream).build();
      assertEquals("TEST-FORMAT", container.getType());
      assertSame(stream, ((CustomContainer) container).getOpenedFromStream());
      assertSame(configuration, ((CustomContainer) container).getConfiguration());
    }
  }

  @Test
  public void openDDocContainerWithTempDirectory() throws Exception {
    File folder = this.testFolder.newFolder();
    assertTrue(folder.list().length == 0);
    ContainerBuilder.aContainer(DDOC).
        fromExistingFile("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc").
        usingTempDirectory(folder.getPath()).build();
    assertTrue(folder.list().length > 0);
  }

  @Test
  public void openDDocContainerWithTempDirectoryAndConfiguration() throws Exception {
    File folder = this.testFolder.newFolder();
    assertTrue(folder.list().length == 0);
    ContainerBuilder.aContainer(DDOC).
        fromExistingFile("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc").
        withConfiguration(Configuration.of(Configuration.Mode.TEST)).usingTempDirectory(folder.getPath()).build();
    assertTrue(folder.list().length > 0);
  }

  @Test
  public void openDDocContainerFromStreamWithTempDirectory() throws Exception {
    File folder = this.testFolder.newFolder();
    assertTrue(folder.list().length == 0);
    InputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE));
    ContainerBuilder.aContainer(DDOC).fromStream(stream).
        usingTempDirectory(folder.getPath()).build();
    assertTrue(folder.list().length > 0);
  }

  @Test
  public void openDDocContainerFromStreamWithTempDirectoryAndConfiguration() throws Exception {
    File folder = this.testFolder.newFolder();
    assertTrue(folder.list().length == 0);
    InputStream stream = FileUtils.openInputStream(new File(DDOC_TEST_FILE));
    ContainerBuilder.aContainer(DDOC).withConfiguration(Configuration.of(Configuration.Mode.TEST))
        .fromStream(stream).usingTempDirectory(folder.getPath()).build();
    assertTrue(folder.list().length > 0);
  }

  @Test
  public void openBOMBeginningDDocContainerFromPath() {
    // TODO (DD4J-1123): Currently JDigiDoc configuration (for validating DDoc containers and signatures) is
    //  automatically initialized only once per process, and thus is dependent on the order the unit tests are run.
    //  This workaround helps to avoid unit test failures caused by incompatible configuration being loaded.
    ConfigManager.init(Configuration.getInstance().getDDoc4JConfiguration());

    Container container = ContainerBuilder.aContainer()
        .fromExistingFile("src/test/resources/testFiles/valid-containers/BOM_algusega.ddoc")
        .build();
    assertTrue(container.validate().isValid());
  }

  @Test
  public void openBOMBeginningDDocContainerFromStream() throws IOException {
    // TODO (DD4J-1123): Currently JDigiDoc configuration (for validating DDoc containers and signatures) is
    //  automatically initialized only once per process, and thus is dependent on the order the unit tests are run.
    //  This workaround helps to avoid unit test failures caused by incompatible configuration being loaded.
    ConfigManager.init(Configuration.getInstance().getDDoc4JConfiguration());

    Container container = ContainerBuilder.aContainer()
        .fromStream(FileUtils.openInputStream(new File("src/test/resources/testFiles/valid-containers/BOM_algusega.ddoc")))
        .build();
    assertTrue(container.validate().isValid());
  }

  @Test
  public void containerBuilder_streamWithZipBomb() throws FileNotFoundException {
    this.expectedException.expect(TechnicalException.class);
    this.expectedException.expectMessage("Zip Bomb detected in the ZIP container. Validation is interrupted.");
    ContainerBuilder.aContainer().
        fromStream(new FileInputStream("src/test/resources/testFiles/invalid-containers/zip-bomb-package-zip-1gb.bdoc")).build();
  }

  @Test
  public void containerBuilder_fileWithZipBomb() {
    this.expectedException.expect(TechnicalException.class);
    this.expectedException.expectMessage("Zip Bomb detected in the ZIP container. Validation is interrupted.");
    ContainerBuilder.aContainer().
        fromExistingFile("src/test/resources/testFiles/invalid-containers/zip-bomb-package-zip-1gb.bdoc").build();
  }

  @Test
  public void containerBuilder_streamWithNestedZipBomb_multipleFiles() throws FileNotFoundException {
    Container container = ContainerBuilder.aContainer().
        fromStream(new FileInputStream("src/test/resources/testFiles/invalid-containers/zip-bomb.asice")).build();
    assertEquals(17, container.getDataFiles().size());
  }

  @Test
  public void containerBuilder_fileWithNestedZipBomb_multipleFiles() {
    Container container = ContainerBuilder.aContainer().
        fromExistingFile("src/test/resources/testFiles/invalid-containers/zip-bomb.asice").build();
    assertEquals(17, container.getDataFiles().size());
  }

  @Test
  public void containerBuilder_streamWithNestedZipBomb() throws FileNotFoundException {
    Container container = ContainerBuilder.aContainer().
        fromStream(new FileInputStream("src/test/resources/testFiles/invalid-containers/zip-bomb-package-zip.asics")).build();
    assertEquals(1, container.getDataFiles().size());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void after() {
    ContainerBuilder.removeCustomContainerImplementations();
  }
}
