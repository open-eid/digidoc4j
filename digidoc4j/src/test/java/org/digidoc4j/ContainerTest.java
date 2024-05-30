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
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.DataFileNotFoundException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.OCSPRequestFailedException;
import org.digidoc4j.exceptions.RemovingDataFileException;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainerBuilder;
import org.digidoc4j.impl.asic.manifest.AsicManifest;
import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.test.MockTSLRefreshCallback;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.digidoc4j.utils.Helper;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

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

public class ContainerTest extends AbstractTest {

  @Test
  public void eIDASAllFailsPolicyConfigurationSuccessfulTest() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    this.configuration.setValidationPolicy
        ("src/test/resources/testFiles/constraints/eIDAS_test_constraint_all_fail_level.xml");
    Container container = this.openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc"));
    SignatureValidationResult result = container.validate();
    Assert.assertTrue("Container is invalid", result.isValid());
  }

  @Test
  public void eIDASWellSignedFailPolicyConfigurationTest() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    this.configuration.setValidationPolicy
        ("src/test/resources/testFiles/constraints/eIDAS_test_constraint_well_signed_fail.xml");
    Container container = this.openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc"));
    SignatureValidationResult result = container.validate();
    Assert.assertTrue("Container is valid", result.isValid());
  }

  @Test
  public void eIDASVersionFailPolicyConfigurationTest() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    this.configuration.setValidationPolicy
        ("src/test/resources/testFiles/constraints/eIDAS_test_constraint_version_fail.xml");
    Container container = this.openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc"));
    SignatureValidationResult result = container.validate();
    Assert.assertFalse("Container is valid", result.isValid());
    TestAssert.assertContainsExactSetOfErrors(result.getErrors(),
            "No acceptable trusted lists has been found!",
            "The trusted list does not have the expected version!"
    );
  }

  @Test
  public void eIDASAllWarningsPolicyConfigurationSuccessfulTest() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    this.configuration.setValidationPolicy
        ("src/test/resources/testFiles/constraints/eIDAS_test_constraint_all_warn_level.xml");
    Container container = this.openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc"));
    SignatureValidationResult result = container.validate();
    Assert.assertTrue("Container is invalid", result.isValid());
  }

  @Test
  public void defaultConfigurationTest() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    Container container = this.openContainerByConfiguration(
        Paths.get("src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc"));
    SignatureValidationResult result = container.validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(0, errors.size());
    Assert.assertTrue(result.isValid());
  }

  @Test
  public void createBDocContainersByDefault() {
    Assert.assertTrue(this.createNonEmptyContainer() instanceof BDocContainer);
  }

  @Test
  public void createBDocContainer() {
    Assert.assertTrue(this.createEmptyContainerBy(Container.DocumentType.BDOC) instanceof BDocContainer);
  }

  @Test(expected = NotSupportedException.class)
  public void createEmptyDDocContainer_throwsException() {
    this.createEmptyContainerBy(Container.DocumentType.DDOC);
  }

  @Test
  public void openBDocContainerWhenTheFileIsAZipAndTheExtensionIsBDoc() {
    Assert.assertTrue(ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/zip_file_without_asics_extension.bdoc") instanceof BDocContainer);
  }

  @Test
  public void openDDocContainerForAllOtherFiles() {
    Assert.assertTrue(ContainerOpener.open(
        "src/test/resources/testFiles/invalid-containers/changed_digidoc_test.ddoc") instanceof DDocContainer);
  }

  @Test
  public void testAddOneFileToContainerForBDoc() {
    Container container = this.createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    List<DataFile> dataFiles = container.getDataFiles();
    Assert.assertEquals(1, dataFiles.size());
    Assert.assertEquals("test.txt", dataFiles.get(0).getName());
    Assert.assertEquals("text/plain", dataFiles.get(0).getMediaType());
  }

  @Test
  public void removeDataFileRemovesFileFromManifest() throws IOException {
    Container nonEmptyContainer = this.createNonEmptyContainer();
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
          Assert.assertFalse(manifestContent.contains("<manifest:file-entry manifest:full-path=\"junit"));
        }
      }
      Assert.assertTrue(manifestVerified);
    }
  }

  @Test(expected = DataFileNotFoundException.class)
  public void wrongObjectBasedDataFileRemovalFromNonEmptyContainer_shouldThrowDataFileNotFoundException() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Assert.assertSame(1, container.getDataFiles().size());
    DataFile differentDataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "some_different_file_name.txt", "text/plain");
    container.removeDataFile(differentDataFile);
  }

  @Test(expected = DataFileNotFoundException.class)
  public void objectBasedDataFileRemovalFromEmptyContainer_shouldThrowDataFileNotFoundException() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    Assert.assertSame(0, container.getDataFiles().size());
    DataFile dataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "some_different_file_name.txt", "text/plain");
    container.removeDataFile(dataFile);
  }

  @Test
  public void objectBasedDataFileRemovalFromCreatedNotSignedContainer_shouldSucceed() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Assert.assertSame(1, container.getDataFiles().size());
    container.removeDataFile(container.getDataFiles().get(0));
    Assert.assertSame(0, container.getDataFiles().size());
  }

  @Test
  public void objectBasedDataFileRemovalFromOpenedNotSignedContainer_shouldSucceed() {
    Container container = this.openContainerBy(Paths.get(ASIC_WITH_NO_SIG));
    Assert.assertSame(1, container.getDataFiles().size());
    container.removeDataFile(container.getDataFiles().get(0));
    Assert.assertSame(0, container.getDataFiles().size());
  }

  @Test(expected = RemovingDataFileException.class)
  public void objectBasedDataFileRemovalFromSignedContainer_shouldThrowRemovingDataFileException() {
    Container container = this.openContainerBy(Paths.get(ASICE_WITH_TS_SIG));
    Assert.assertSame(1, container.getDataFiles().size());
    container.removeDataFile(container.getDataFiles().get(0));
  }

  @Test
  public void testCreateBDocContainerSpecifiedByDocumentTypeForBDoc() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    TestDataBuilderUtil.signContainer(container);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    Assert.assertTrue(Helper.isZipFile(new File(file)));
  }

  @Test(expected = NotSupportedException.class)
  public void createEmptyDDoc_throwsException() {
    ContainerBuilder.aContainer(Container.DocumentType.DDOC).build();
  }

  @Test(expected = NotSupportedException.class)
  public void DDocRemovingDataFile_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.removeDataFile(container.getDataFiles().get(0));
  }

  @Test(expected = NotSupportedException.class)
  public void DDocAddDataFile_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = NotSupportedException.class)
  public void DDocExtendSignatureProfile_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.extendSignatureProfile(SignatureProfile.LT_TM);
  }

  @Test
  public void addLargeFileToBDoc() {
    DataFile dataFile = new LargeDataFile(new ByteArrayInputStream(new byte[]{0, 1, 2, 3}), "large-doc.txt",
        "text/plain");
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile(dataFile);
    Assert.assertEquals(1, container.getDataFiles().size());
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = this.openContainerBy(Paths.get(file));
    Assert.assertEquals(1, container.getDataFiles().size());
    Assert.assertEquals("large-doc.txt", container.getDataFiles().get(0).getName());
  }

  @Test
  public void addingDataFileToAlreadySignedContainer_shouldThrowDigiDoc4JException() {
    expectedException.expect(DigiDoc4JException.class);
    expectedException.expectMessage("Datafiles cannot be added to an already signed container");

    Container container = this.openContainerBy(Paths.get(ASICE_WITH_TS_SIG));
    Assert.assertSame(1, container.getDataFiles().size());
    DataFile newDataFile = new DataFile("something".getBytes(StandardCharsets.UTF_8), "new_data_file.txt", "text/plain");
    container.addDataFile(newDataFile);
  }

  @Test
  public void testOpenCreatedDDocFile() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    String file = this.getFileBy("ddoc");
    container.saveAsFile(file);
    Container containerForReading = ContainerOpener.open(file);
    Assert.assertEquals(Constant.DDOC_CONTAINER_TYPE, containerForReading.getType());
    Assert.assertEquals(1, container.getDataFiles().size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenInvalidFileReturnsError() {
    ContainerOpener.open("src/test/resources/testFiles/helper-files/test.txt");
  }

  @Test
  public void testValidateDDoc() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
    Assert.assertFalse(result.hasWarnings());
  }

  @Ignore //This test fails in Travis
  @Test
  public void testValidateDDoc10() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener.open("src/test/resources/prodFiles/valid-containers/SK-XML1.0.ddoc");
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
    Assert.assertTrue(result.hasWarnings());
    Assert.assertEquals(177, result.getWarnings().get(0).getErrorCode());
    Assert.assertTrue(result.getReport().contains("Old and unsupported format:"));
  }

  @Test
  public void testValidateDDoc11() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener.open("src/test/resources/prodFiles/valid-containers/DIGIDOC-XML1.1.ddoc");
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
    Assert.assertTrue(result.hasWarnings());
    Assert.assertEquals(177, result.getWarnings().get(0).getErrorCode());
    Assert.assertTrue(result.getReport().contains("Old and unsupported format:"));
  }

  @Test
  public void testValidateDDoc12() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener.open("src/test/resources/prodFiles/valid-containers/DIGIDOC-XML1.2.ddoc");
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
    Assert.assertTrue(result.hasWarnings());
    Assert.assertEquals(177, result.getWarnings().get(0).getErrorCode());
    Assert.assertTrue(result.getReport().contains("Old and unsupported format:"));
  }

  @Test
  public void openDDocContainerFromFile() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerBuilder.aContainer(Container.DocumentType.DDOC).
        fromExistingFile("src/test/resources/testFiles/valid-containers/ddoc_wo_x509IssueName_xmlns.ddoc").build();
    SignatureValidationResult validate = container.validate();
    Assert.assertTrue(validate.isValid());
    Assert.assertEquals(0, validate.getErrors().size());
    Assert.assertTrue(validate.getReport().contains("X509IssuerName has none or invalid namespace:"));
    Assert.assertTrue(validate.getReport().contains("X509SerialNumber has none or invalid namespace:"));
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenNotExistingFileThrowsException() {
    ContainerOpener.open("noFile.ddoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenEmptyFileThrowsException() {
    ContainerOpener.open("src/test/resources/testFiles/invalid-containers/emptyFile.ddoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testFileTooShortToVerifyIfItIsZipFileThrowsException() {
    ContainerOpener.open("src/test/resources/testFiles/invalid-containers/tooShortToVerifyIfIsZip.ddoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenFromStreamTooShortToVerifyIfIsZip() {
    try (FileInputStream stream = new FileInputStream(
        "src/test/resources/testFiles/invalid-containers/tooShortToVerifyIfIsZip.ddoc")) {
      ContainerOpener.open(stream, true);
    } catch (DigiDoc4JException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test(expected = NotSupportedException.class)
  public void testAddFileFromStreamToDDoc() throws IOException {
    Container container = this.createEmptyContainerBy(Container.DocumentType.DDOC);
    try (ByteArrayInputStream is = new ByteArrayInputStream(new byte[]{0x42})) {
      container.addDataFile(is, "testFromStream.txt", "text/plain");
    }
  }

  @Test
  public void openContainerFromStreamAsBDoc() throws IOException {
    Container container = this.createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    try (FileInputStream stream = new FileInputStream(file)) {
      Container containerToTest = ContainerOpener.open(stream, false);
      Assert.assertEquals(1, containerToTest.getSignatures().size());
    }
  }

  @Test
  public void openContainerFromStreamAsDDoc() throws IOException {
    try (FileInputStream stream = new FileInputStream(
        "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc")) {
      Container container = ContainerOpener.open(stream, false);
      Assert.assertEquals(1, container.getSignatures().size());
    }
  }

  @Test
  public void testGetSignatureFromDDoc() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    List<Signature> signatures = container.getSignatures();
    Assert.assertEquals(1, signatures.size());
  }

  @Test
  public void testConfigurationIsKeptWithInDDoc() {
    DDocContainer container = (DDocContainer) ContainerBuilder.aContainer(Container.DocumentType.DDOC)
        .withConfiguration(Configuration.getInstance())
        .fromExistingFile("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc")
        .build();
    Assert.assertEquals(Configuration.getInstance(), container.getDDoc4JFacade().getConfiguration());
  }

  @Test
  public void testExtendSignatureProfileForBDOC() {
    Container container = this.createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.aSignature(container).withSignatureProfile(SignatureProfile.B_BES).
        withSignatureToken(pkcs12SignatureToken).invokeSigning();
    container.addSignature(signature);
    container.extendSignatureProfile(SignatureProfile.LT);
    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemovingNotExistingSignatureThrowsException() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.DDOC);
    Signature signature = SignatureBuilder.aSignature(container).withSignatureProfile(SignatureProfile.LT_TM).
            withSignatureToken(pkcs12SignatureToken).invokeSigning();
    container.removeSignature(signature);
  }


  @Test
  public void testSigningWithSignerInfo() {
    Container container = this.createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.aSignature(container).withCity("myCity").withStateOrProvince(
        "myStateOrProvince").
        withPostalCode("myPostalCode").withCountry("myCountry").withRoles("myRole / myResolution").
        withSignatureToken(pkcs12SignatureToken).invokeSigning();
    container.addSignature(signature);
    Assert.assertEquals("myCity", signature.getCity());
    Assert.assertEquals("myStateOrProvince", signature.getStateOrProvince());
    Assert.assertEquals("myPostalCode", signature.getPostalCode());
    Assert.assertEquals("myCountry", signature.getCountryName());
    Assert.assertEquals(1, signature.getSignerRoles().size());
    Assert.assertEquals("myRole / myResolution", signature.getSignerRoles().get(0));
  }

  @Test
  public void testSetConfigurationForBDoc() {
    expectedException.expect(OCSPRequestFailedException.class);
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.configuration.setTslRefreshCallback(new MockTSLRefreshCallback(true));
    this.configuration.setLotlLocation("pole");
    Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC).withConfiguration(
        this.configuration).
        withDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain").build();
    this.createSignatureBy(container, pkcs12SignatureToken);
  }

  @Test
  public void mustBePossibleToCreateAndVerifyContainerWhereDigestAlgorithmIsSHA224() {
    Container container = this.createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA224).
        withSignatureToken(pkcs12SignatureToken).invokeSigning();
    container.addSignature(signature);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha224",
        container.getSignatures().get(0).getSignatureMethod());
  }

  @Test
  public void mustBePossibleToCreateContainerWithTSignatureProfile() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    Container container = ContainerBuilder
            .aContainer(Container.DocumentType.ASICE)
            .withConfiguration(this.configuration)
            .withDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain").build();
    this.createSignatureBy(container, SignatureProfile.T, pkcs12SignatureToken);
    ContainerValidationResult validationResult = container.validate();
    Assert.assertEquals(SignatureLevel.XAdES_BASELINE_T, validationResult.getReports().get(0).getSignatureFormat());
    Assert.assertEquals(SignatureProfile.T, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void constructorWithConfigurationParameter() {
    Container container = ContainerBuilder.aContainer().
        withConfiguration(Configuration.getInstance()).build();
    Assert.assertEquals("ASICE", container.getType());
  }

  @Test
  public void createContainerWhenAttachmentNameContainsEstonianCharacters() {
    Container container = this.createEmptyContainer();
    String s = "\u0303a\u0308o\u0308u\u0308";
    container.addDataFile(new DataFile(
            s.getBytes(StandardCharsets.UTF_8),
            s + ".txt",
            "text/plain"
    ));
    createSignatureBy(container, pkcs12SignatureToken);
    Assert.assertEquals(1, container.getDataFiles().size());
    TestAssert.assertContainerIsValid(container);
  }

  @Test
  public void containerTypeStringValueForBDOC() {
    Assert.assertEquals("application/vnd.etsi.asic-e+zip",
        Container.DocumentType.BDOC.toString());
  }

  @Test
  public void testSigningMultipleFilesInContainer() {
    Container container = this.createEmptyContainer();
    container.addDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "1.txt", "text/plain");
    container.addDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "2.txt", "text/plain");
    container.addDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "3.txt", "text/plain");
    TestDataBuilderUtil.signContainer(container);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    Assert.assertEquals(3, container.getDataFiles().size());
    this.assertContainsDataFile("1.txt", container);
    this.assertContainsDataFile("2.txt", container);
    this.assertContainsDataFile("3.txt", container);
    Container openedContainer = ContainerOpener.open(file);
    Assert.assertEquals(3, openedContainer.getDataFiles().size());
    this.assertContainsDataFile("1.txt", openedContainer);
    this.assertContainsDataFile("2.txt", openedContainer);
    this.assertContainsDataFile("3.txt", openedContainer);
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
    Assert.fail("Data file '" + fileName + "' was not found in the container");
  }

}
