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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.DataFileNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.OCSPRequestFailedException;
import org.digidoc4j.exceptions.RemovingDataFileException;
import org.digidoc4j.impl.CommonOCSPSource;
import org.digidoc4j.impl.OcspDataLoaderFactory;
import org.digidoc4j.impl.SKOnlineOCSPSource;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainerBuilder;
import org.digidoc4j.impl.asic.manifest.AsicManifest;
import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.test.MockTSLRefreshCallback;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.digidoc4j.utils.Helper;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.digidoc4j.test.TestAssert.assertContainerIsInvalid;
import static org.digidoc4j.test.TestAssert.assertContainerIsValid;
import static org.digidoc4j.test.TestAssert.assertContainsExactSetOfErrors;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class ContainerTest extends AbstractTest {

  @Test
  public void eIDASAllFailsPolicyConfigurationSuccessfulTest() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setValidationPolicy
        ("src/test/resources/testFiles/constraints/eIDAS_test_constraint_all_fail_level.xml");
    Container container = openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc"));
    ContainerValidationResult result = container.validate();
    assertContainerIsValid(result);
  }

  @Test
  public void eIDASWellSignedFailPolicyConfigurationTest() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setValidationPolicy
        ("src/test/resources/testFiles/constraints/eIDAS_test_constraint_well_signed_fail.xml");
    Container container = openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc"));
    ContainerValidationResult result = container.validate();
    assertContainerIsValid(result);
  }

  @Test
  public void eIDASVersionFailPolicyConfigurationTest() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setValidationPolicy
        ("src/test/resources/testFiles/constraints/eIDAS_test_constraint_version_fail.xml");
    Container container = openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc"));
    ContainerValidationResult result = container.validate();
    assertContainerIsInvalid(result);
    assertContainsExactSetOfErrors(result.getErrors(),
            "No acceptable trusted lists has been found!",
            "The trusted list does not have the expected version!"
    );
  }

  @Test
  public void eIDASAllWarningsPolicyConfigurationSuccessfulTest() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    configuration.setValidationPolicy
        ("src/test/resources/testFiles/constraints/eIDAS_test_constraint_all_warn_level.xml");
    Container container = openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc"));
    ContainerValidationResult result = container.validate();
    assertContainerIsValid(result);
  }

  @Test
  public void defaultConfigurationTest() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    Container container = openContainerByConfiguration(
         Paths.get("src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc"));
    ContainerValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(0, errors.size());
    assertContainerIsValid(result);
  }

  @Test
  public void createBDocContainersByDefault() {
    assertInstanceOf(BDocContainer.class, createNonEmptyContainer());
  }

  @Test
  public void createBDocContainer() {
    assertInstanceOf(BDocContainer.class, createEmptyContainerBy(Container.DocumentType.BDOC));
  }

  @Test
  public void createEmptyDDocContainer_throwsException() {
    assertThrows(
            NotSupportedException.class,
            () -> createEmptyContainerBy(Container.DocumentType.DDOC)
    );
  }

  @Test
  public void openBDocContainerWhenTheFileIsAZipAndTheExtensionIsBDoc() {
    assertInstanceOf(
            BDocContainer.class,
            ContainerOpener.open("src/test/resources/testFiles/invalid-containers/zip_file_without_asics_extension.bdoc"));
  }

  @Test
  public void openDDocContainerForAllOtherFiles() {
    assertInstanceOf(
            DDocContainer.class,
            ContainerOpener.open("src/test/resources/testFiles/invalid-containers/changed_digidoc_test.ddoc"));
  }

  @Test
  public void testAddOneFileToContainerForBDoc() {
    Container container = createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    List<DataFile> dataFiles = container.getDataFiles();
    assertEquals(1, dataFiles.size());
    assertEquals("test.txt", dataFiles.get(0).getName());
    assertEquals("text/plain", dataFiles.get(0).getMediaType());
  }

  @Test
  public void removeDataFileRemovesFileFromManifest() throws IOException {
    Container nonEmptyContainer = createNonEmptyContainer();
    Container container = BDocContainerBuilder
            .aContainer()
            .fromStream(nonEmptyContainer.saveAsStream())
            .withConfiguration(configuration)
            .build();

    container.removeDataFile(container.getDataFiles().get(0));

    InputStream inputStream = container.saveAsStream();
    boolean manifestVerified = false;
    try (ZipInputStream zis = new ZipInputStream(inputStream)) {
      ZipEntry zipEntry;
      while ((zipEntry = zis.getNextEntry()) != null) {
        if (zipEntry.getName().equals(AsicManifest.XML_PATH)) {
          manifestVerified = true;
          String manifestContent = IOUtils.toString(zis, StandardCharsets.UTF_8);
          assertFalse(manifestContent.contains("<manifest:file-entry manifest:full-path=\"junit"));
        }
      }
      assertTrue(manifestVerified);
    }
  }

  @Test
  public void wrongObjectBasedDataFileRemovalFromNonEmptyContainer_shouldThrowDataFileNotFoundException() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    assertSame(1, container.getDataFiles().size());
    DataFile differentDataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "some_different_file_name.txt", "text/plain");

    assertThrows(
            DataFileNotFoundException.class,
            () -> container.removeDataFile(differentDataFile)
    );
  }

  @Test
  public void objectBasedDataFileRemovalFromEmptyContainer_shouldThrowDataFileNotFoundException() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    assertSame(0, container.getDataFiles().size());
    DataFile dataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "some_different_file_name.txt", "text/plain");

    assertThrows(
            DataFileNotFoundException.class,
            () -> container.removeDataFile(dataFile)
    );
  }

  @Test
  public void objectBasedDataFileRemovalFromCreatedNotSignedContainer_shouldSucceed() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    assertSame(1, container.getDataFiles().size());
    container.removeDataFile(container.getDataFiles().get(0));
    assertSame(0, container.getDataFiles().size());
  }

  @Test
  public void objectBasedDataFileRemovalFromOpenedNotSignedContainer_shouldSucceed() {
    Container container = openContainerBy(Paths.get(ASIC_WITH_NO_SIG));
    assertSame(1, container.getDataFiles().size());
    container.removeDataFile(container.getDataFiles().get(0));
    assertSame(0, container.getDataFiles().size());
  }

  @Test
  public void objectBasedDataFileRemovalFromSignedContainer_shouldThrowRemovingDataFileException() {
    Container container = openContainerBy(Paths.get(ASICE_WITH_TS_SIG));
    assertSame(1, container.getDataFiles().size());

    assertThrows(
            RemovingDataFileException.class,
            () -> container.removeDataFile(container.getDataFiles().get(0))
    );
  }

  @Test
  public void testCreateBDocContainerSpecifiedByDocumentTypeForBDoc() throws Exception {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    TestDataBuilderUtil.signContainer(container);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    assertTrue(Helper.isZipFile(new File(file)));
  }

  @Test
  public void createEmptyDDoc_throwsException() {
    assertThrows(
            NotSupportedException.class,
            () -> ContainerBuilder.aContainer(Container.DocumentType.DDOC).build()
    );
  }

  @Test
  public void DDocRemovingDataFile_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");

    assertThrows(
            NotSupportedException.class,
            () -> container.removeDataFile(container.getDataFiles().get(0))
    );
  }

  @Test
  public void DDocAddDataFile_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");

    assertThrows(
            NotSupportedException.class,
            () -> container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain")
    );
  }

  @Test
  public void DDocExtendSignatureProfile_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");

    assertThrows(
            NotSupportedException.class,
            () -> container.extendSignatureProfile(SignatureProfile.LT_TM)
    );
  }

  @Test
  public void addLargeFileToBDoc() {
    DataFile dataFile = new LargeDataFile(new ByteArrayInputStream(new byte[]{0, 1, 2, 3}), "large-doc.txt",
        "text/plain");
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile(dataFile);
    assertEquals(1, container.getDataFiles().size());
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = openContainerBy(Paths.get(file));
    assertEquals(1, container.getDataFiles().size());
    assertEquals("large-doc.txt", container.getDataFiles().get(0).getName());
  }

  @Test
  public void addingDataFileToAlreadySignedContainer_shouldThrowDigiDoc4JException() {
    Container container = openContainerBy(Paths.get(ASICE_WITH_TS_SIG));
    assertSame(1, container.getDataFiles().size());
    DataFile newDataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "new_data_file.txt", "text/plain");

    DigiDoc4JException exception = assertThrows(
            DigiDoc4JException.class,
            () -> container.addDataFile(newDataFile)
    );

    assertThat(exception.getMessage(), containsString("Datafiles cannot be added to an already signed container"));
  }

  @Test
  public void testOpenCreatedDDocFile() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    String file = getFileBy("ddoc");
    container.saveAsFile(file);
    Container containerForReading = ContainerOpener.open(file);
    assertEquals(Constant.DDOC_CONTAINER_TYPE, containerForReading.getType());
    assertEquals(1, container.getDataFiles().size());
  }

  @Test
  public void testOpenInvalidFileReturnsError() {
    assertThrows(
            DigiDoc4JException.class,
            () -> ContainerOpener.open("src/test/resources/testFiles/helper-files/test.txt")
    );
  }

  @Test
  public void testValidateDDoc() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    SignatureValidationResult result = container.validate();
    assertTrue(result.isValid());
    assertFalse(result.hasWarnings());
  }

  @Test
  public void testValidateDDoc10() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerOpener.open("src/test/resources/prodFiles/valid-containers/SK-XML1.0.ddoc");
    SignatureValidationResult result = container.validate();
    assertTrue(result.isValid());
    assertTrue(result.hasWarnings());
    assertEquals(177, result.getWarnings().get(0).getErrorCode());
    assertTrue(result.getReport().contains("Old and unsupported format:"));
  }

  @Test
  public void testValidateDDoc11() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerOpener.open("src/test/resources/prodFiles/valid-containers/DIGIDOC-XML1.1.ddoc");
    SignatureValidationResult result = container.validate();
    assertTrue(result.isValid());
    assertTrue(result.hasWarnings());
    assertEquals(177, result.getWarnings().get(0).getErrorCode());
    assertTrue(result.getReport().contains("Old and unsupported format:"));
  }

  @Test
  public void testValidateDDoc12() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerOpener.open("src/test/resources/prodFiles/valid-containers/DIGIDOC-XML1.2.ddoc");
    SignatureValidationResult result = container.validate();
    assertTrue(result.isValid());
    assertTrue(result.hasWarnings());
    assertEquals(177, result.getWarnings().get(0).getErrorCode());
    assertTrue(result.getReport().contains("Old and unsupported format:"));
  }

  @Test
  public void openDDocContainerFromFile() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(configuration);
    Container container = ContainerBuilder.aContainer(Container.DocumentType.DDOC).
        fromExistingFile("src/test/resources/testFiles/valid-containers/ddoc_wo_x509IssueName_xmlns.ddoc").build();
    SignatureValidationResult validate = container.validate();
    assertTrue(validate.isValid());
    assertEquals(0, validate.getErrors().size());
    assertTrue(validate.getReport().contains("X509IssuerName has none or invalid namespace:"));
    assertTrue(validate.getReport().contains("X509SerialNumber has none or invalid namespace:"));
  }

  @Test
  public void testOpenNotExistingFileThrowsException() {
    assertThrows(
            DigiDoc4JException.class,
            () -> ContainerOpener.open("noFile.ddoc")
    );
  }

  @Test
  public void testOpenEmptyFileThrowsException() {
    assertThrows(
            DigiDoc4JException.class,
            () -> ContainerOpener.open("src/test/resources/testFiles/invalid-containers/emptyFile.ddoc")
    );
  }

  @Test
  public void testFileTooShortToVerifyIfItIsZipFileThrowsException() {
    assertThrows(
            DigiDoc4JException.class,
            () -> ContainerOpener.open("src/test/resources/testFiles/invalid-containers/tooShortToVerifyIfIsZip.ddoc")
    );
  }

  @Test
  public void testOpenFromStreamTooShortToVerifyIfIsZip() throws IOException {
    try (FileInputStream stream = new FileInputStream(
            "src/test/resources/testFiles/invalid-containers/tooShortToVerifyIfIsZip.ddoc")) {
      assertThrows(
              DigiDoc4JException.class,
              () -> ContainerOpener.open(stream, true)
      );
    }
  }

  @Test
  public void testAddFileFromStreamToDDoc() throws IOException {
    Container container = createEmptyContainerBy(Container.DocumentType.DDOC);
    try (ByteArrayInputStream is = new ByteArrayInputStream(new byte[]{0x42})) {
      assertThrows(
              NotSupportedException.class,
              () -> container.addDataFile(is, "testFromStream.txt", "text/plain")
      );
    }
  }

  @Test
  public void openContainerFromStreamAsBDoc() throws IOException {
    Container container = createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    createSignatureBy(container, pkcs12SignatureToken);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    try (FileInputStream stream = new FileInputStream(file)) {
      Container containerToTest = ContainerOpener.open(stream, false);
      assertEquals(1, containerToTest.getSignatures().size());
    }
  }

  @Test
  public void openContainerFromStreamAsDDoc() throws IOException {
    try (FileInputStream stream = new FileInputStream(
        "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc")) {
      Container container = ContainerOpener.open(stream, false);
      assertEquals(1, container.getSignatures().size());
    }
  }

  @Test
  public void testGetSignatureFromDDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    List<Signature> signatures = container.getSignatures();
    assertEquals(1, signatures.size());
  }

  @Test
  public void testConfigurationIsKeptWithInDDoc() {
    DDocContainer container = (DDocContainer) ContainerBuilder.aContainer(Container.DocumentType.DDOC)
        .withConfiguration(Configuration.getInstance())
        .fromExistingFile("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc")
        .build();
    assertEquals(Configuration.getInstance(), container.getDDoc4JFacade().getConfiguration());
  }

  @Test
  public void testExtendSignatureProfileForBDOC() {
    configuration = Configuration.of(Configuration.Mode.TEST);

    SKOnlineOCSPSource source = new CommonOCSPSource(configuration);
    DataLoader loader = new OcspDataLoaderFactory(configuration).create();
    source.setDataLoader(loader);
    configuration.setExtendingOcspSourceFactory(() -> source);

    Container container = createEmptyContainer(configuration);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder
            .aSignature(container)
            .withSignatureProfile(SignatureProfile.B_BES)
            .withSignatureToken(pkcs12SignatureToken)
            .invokeSigning();
    container.addSignature(signature);
    container.extendSignatureProfile(SignatureProfile.LT);
    assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
  }

  @Test
  public void testRemovingNotExistingSignatureThrowsException() {
      Container container = createEmptyContainerBy(Container.DocumentType.DDOC);
      Signature signature = SignatureBuilder
              .aSignature(container).withSignatureProfile(SignatureProfile.LT_TM).
              withSignatureToken(pkcs12SignatureToken)
              .invokeSigning();

      assertThrows(
              DigiDoc4JException.class,
              () -> container.removeSignature(signature));
  }

  @Test
  public void testSigningWithSignerInfo() {
    Container container = createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.aSignature(container).withCity("myCity").withStateOrProvince(
        "myStateOrProvince").
        withPostalCode("myPostalCode").withCountry("myCountry").withRoles("myRole / myResolution").
        withSignatureToken(pkcs12SignatureToken).invokeSigning();
    container.addSignature(signature);
    assertEquals("myCity", signature.getCity());
    assertEquals("myStateOrProvince", signature.getStateOrProvince());
    assertEquals("myPostalCode", signature.getPostalCode());
    assertEquals("myCountry", signature.getCountryName());
    assertEquals(1, signature.getSignerRoles().size());
    assertEquals("myRole / myResolution", signature.getSignerRoles().get(0));
  }

  @Test
  public void testSetConfigurationForBDoc() {
    configuration = new Configuration(Configuration.Mode.TEST);
    configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    configuration.setLotlLocation("pole");
    Container container = ContainerBuilder
            .aContainer(Container.DocumentType.BDOC)
            .withConfiguration(configuration)
            .withDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain").build();

    assertThrows(
            OCSPRequestFailedException.class,
            () -> createSignatureBy(container, pkcs12SignatureToken)
    );
  }

  @Test
  public void mustBePossibleToCreateAndVerifyContainerWhereDigestAlgorithmIsSHA224() {
    Container container = createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA224).
        withSignatureToken(pkcs12SignatureToken).invokeSigning();
    container.addSignature(signature);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha224",
        container.getSignatures().get(0).getSignatureMethod());
  }

  @Test
  public void mustBePossibleToCreateContainerWithTSignatureProfile() {
    configuration = new Configuration(Configuration.Mode.TEST);
    Container container = ContainerBuilder
            .aContainer(Container.DocumentType.ASICE)
            .withConfiguration(configuration)
            .withDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain").build();
    createSignatureBy(container, SignatureProfile.T, pkcs12SignatureToken);
    ContainerValidationResult validationResult = container.validate();
    assertEquals(SignatureLevel.XAdES_BASELINE_T, validationResult.getReports().get(0).getSignatureFormat());
    assertEquals(SignatureProfile.T, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void constructorWithConfigurationParameter() {
    Container container = ContainerBuilder.aContainer().
        withConfiguration(Configuration.getInstance()).build();
    assertEquals("ASICE", container.getType());
  }

  @Test
  public void createContainerWhenAttachmentNameContainsEstonianCharacters() {
    Container container = createEmptyContainer();
    String s = "\u0303a\u0308o\u0308u\u0308";
    container.addDataFile(new DataFile(
            s.getBytes(StandardCharsets.UTF_8),
            s + ".txt",
            "text/plain"
    ));
    createSignatureBy(container, pkcs12SignatureToken);
    assertEquals(1, container.getDataFiles().size());
    assertContainerIsValid(container);
  }

  @Test
  public void containerTypeStringValueForBDOC() {
    assertEquals("application/vnd.etsi.asic-e+zip",
        Container.DocumentType.BDOC.toString());
  }

  @Test
  public void testSigningMultipleFilesInContainer() {
    Container container = createEmptyContainer();
    container.addDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "1.txt", "text/plain");
    container.addDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "2.txt", "text/plain");
    container.addDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "3.txt", "text/plain");
    TestDataBuilderUtil.signContainer(container);
    String file = getFileBy("bdoc");
    container.saveAsFile(file);
    assertEquals(3, container.getDataFiles().size());
    assertContainsDataFile("1.txt", container);
    assertContainsDataFile("2.txt", container);
    assertContainsDataFile("3.txt", container);
    Container openedContainer = ContainerOpener.open(file);
    assertEquals(3, openedContainer.getDataFiles().size());
    assertContainsDataFile("1.txt", openedContainer);
    assertContainsDataFile("2.txt", openedContainer);
    assertContainsDataFile("3.txt", openedContainer);
  }

  /*
   * RESTRICTED METHODS
   */


  private void assertContainsDataFile(String fileName, Container container) {
    for (DataFile file : container.getDataFiles()) {
      if (StringUtils.equals(fileName, file.getName())) {
        return;
      }
    }
    fail("Data file '" + fileName + "' was not found in the container");
  }

}
