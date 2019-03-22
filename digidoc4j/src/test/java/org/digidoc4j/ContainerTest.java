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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.TslCertificateSourceInitializationException;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.digidoc4j.utils.Helper;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.util.List;

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
    Assert.assertEquals("No errors count match", 2, result.getErrors().size());
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
    Assert.assertTrue(errors.size() == 0);
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
  public void testAddOneFileToContainerForBDoc() throws Exception {
    Container container = this.createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    List<DataFile> dataFiles = container.getDataFiles();
    Assert.assertEquals(1, dataFiles.size());
    Assert.assertEquals("test.txt", dataFiles.get(0).getName());
    Assert.assertEquals("text/plain", dataFiles.get(0).getMediaType());
  }

  @Test
  public void testRemovesOneFileFromContainerWhenFileExistsForBDoc() throws Exception {
    Container container = this.createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.removeDataFile("test.txt");
    Assert.assertEquals(0, container.getDataFiles().size());
  }

  @Test
  public void testCreateBDocContainerSpecifiedByDocumentTypeForBDoc() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    TestDataBuilderUtil.signContainer(container);
    String file = this.getFileBy("bdoc");
    container.save(file);
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
  public void DDocPrepareSigning_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.prepareSigning(this.pkcs12SignatureToken.getCertificate());
  }

  @Test(expected = NotSupportedException.class)
  public void DDocSign_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.sign(pkcs12SignatureToken);
  }

  @Test(expected = NotSupportedException.class)
  public void DDocSignRaw_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.signRaw(new byte[] {0});
  }

  @Test(expected = NotSupportedException.class)
  public void DDocAddRawSignature_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.addRawSignature(new byte[] {0});
  }

  @Test(expected = NotSupportedException.class)
  public void DDocAddRawSignatureAsStreamArray_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.addRawSignature(new ByteArrayInputStream(new byte[] {0}));
  }

  @Test(expected = NotSupportedException.class)
  public void DDocAddDataFile_throwsException() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = NotSupportedException.class)
  public void DDocExtendTo_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.extendTo(SignatureProfile.LT_TM);
  }

  @Test(expected = NotSupportedException.class)
  public void DDocExtendSignatureProfile_throwsException() {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.extendSignatureProfile(SignatureProfile.LT_TM);
  }

  @Test
  public void addLargeFileToBDoc() throws Exception {
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
  public void testOpenCreatedDDocFile() throws Exception {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    String file = this.getFileBy("ddoc");
    container.save(file);
    Container containerForReading = ContainerOpener.open(file);
    Assert.assertEquals(Container.DocumentType.DDOC, containerForReading.getDocumentType());
    Assert.assertEquals(1, container.getDataFiles().size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenInvalidFileReturnsError() {
    ContainerOpener.open("src/test/resources/testFiles/helper-files/test.txt");
  }

  @Test
  public void testValidateDDoc() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener.open(
        "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertTrue(container.validate().isValid());
    Assert.assertFalse(container.validate().hasWarnings());
  }

  @Ignore //This test fails in Travis
  @Test
  public void testValidateDDoc10() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener.open("src/test/resources/prodFiles/valid-containers/SK-XML1.0.ddoc");
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(container.validate().isValid());
    Assert.assertTrue(container.validate().hasWarnings());
    Assert.assertEquals(177, result.getWarnings().get(0).getErrorCode());
    Assert.assertTrue(result.getReport().contains("Old and unsupported format:"));
  }

  @Test
  public void testValidateDDoc11() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener.open("src/test/resources/prodFiles/valid-containers/DIGIDOC-XML1.1.ddoc");
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(container.validate().isValid());
    Assert.assertTrue(container.validate().hasWarnings());
    Assert.assertEquals(177, result.getWarnings().get(0).getErrorCode());
    Assert.assertTrue(result.getReport().contains("Old and unsupported format:"));
  }

  @Test
  public void testValidateDDoc12() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    Container container = ContainerOpener.open("src/test/resources/prodFiles/valid-containers/DIGIDOC-XML1.2.ddoc");
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(container.validate().isValid());
    Assert.assertTrue(container.validate().hasWarnings());
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
        new File("src/test/resources/testFiles/invalid-containers/tooShortToVerifyIfIsZip.ddoc"))) {
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
    Signature signature = this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = this.getFileBy("bdoc");
    container.save(file);
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
  public void testConfigurationIsKeptWithInDDoc() throws Exception {
    DDocContainer container = (DDocContainer) ContainerBuilder.aContainer(Container.DocumentType.DDOC)
            .withConfiguration(Configuration.getInstance())
            .fromExistingFile("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc")
            .build();
    Assert.assertEquals(Configuration.getInstance(), container.getDDoc4JFacade().getConfiguration());
  }

  @Test
  public void testExtendToForBDOC() {
    Container container = this.createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.aSignature(container).withSignatureProfile(SignatureProfile.B_BES).
        withSignatureToken(this.pkcs12SignatureToken).invokeSigning();
    container.addSignature(signature);
    container.extendTo(SignatureProfile.LT);
    Assert.assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test
  public void addRawSignatureToBDocContainer() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    byte[] signatureBytes = FileUtils.readFileToByteArray(
        new File("src/test/resources/testFiles/xades/valid-bdoc-tm.xml"));
    container.addRawSignature(signatureBytes);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void addRawSignatureToExistingBDocContainer() throws Exception {
    Container container = this.createNonEmptyContainerBy(
        Paths.get("src/test/resources/testFiles/helper-files/test.txt"));
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    byte[] signatureBytes = FileUtils.readFileToByteArray(
        new File("src/test/resources/testFiles/xades/valid-bdoc-tm.xml"));
    container.addRawSignature(signatureBytes);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals(2, container.getSignatures().size());
    TestAssert.assertContainerIsValid(container);
  }

  @Test(expected = InvalidSignatureException.class)
  public void testAddRawSignatureAsByteArrayForBDoc() throws CertificateEncodingException, IOException, SAXException {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    container.addRawSignature(Base64.decodeBase64("fo4aA1PVI//1agzBm2Vcxj7sk9pYQJt+9a7xLFSkfF10RocvGjVPBI65RMqyxGIsje" +
        "LoeDERfTcjHdNojoK/gEdKtme4z6kvkZzjMjDuJu7krK/3DHBtW3XZleIaWZSWySahUiPNNIuk5ykACUolh+K/UK2aWL3Nh64EWvC8aznLV0" +
        "M21s7GwTv7+iVXhR/6c3O22saWKWsteGT0/AqfcBRoj13H/NyuZOULqU0PFOhbJtV8RyZgC9n2uYBFsnutt5GPvhP+U93gkmFQ0+iC1a9Ktt" +
        "j4QH5si35YmRIe0fp8tGDo6li63/tybb+kQ96AIaRe1NxpkKVDBGNi+VNVNA=="));
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemovingNotExistingSignatureThrowsException() {
    Container container = this.createEmptyContainerBy(Container.DocumentType.DDOC);
    container.removeSignature(0);
  }


  @Test
  public void testSigningWithSignerInfo() throws Exception {
    Container container = this.createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.aSignature(container).withCity("myCity").withStateOrProvince(
        "myStateOrProvince").
        withPostalCode("myPostalCode").withCountry("myCountry").withRoles("myRole / myResolution").
        withSignatureToken(this.pkcs12SignatureToken).invokeSigning();
    container.addSignature(signature);
    Assert.assertEquals("myCity", signature.getCity());
    Assert.assertEquals("myStateOrProvince", signature.getStateOrProvince());
    Assert.assertEquals("myPostalCode", signature.getPostalCode());
    Assert.assertEquals("myCountry", signature.getCountryName());
    Assert.assertEquals(1, signature.getSignerRoles().size());
    Assert.assertEquals("myRole / myResolution", signature.getSignerRoles().get(0));
  }

  @Test(expected = TslCertificateSourceInitializationException.class)
  public void testSetConfigurationForBDoc() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.configuration.setTslLocation("pole");
    Container container = ContainerBuilder.aContainer(Container.DocumentType.BDOC).withConfiguration(
        this.configuration).
        withDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain").build();
    this.createSignatureBy(container, this.pkcs12SignatureToken);
  }

  @Test
  public void mustBePossibleToCreateAndVerifyContainerWhereDigestAlgorithmIsSHA224() throws Exception {
    Container container = this.createEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Signature signature = SignatureBuilder.aSignature(container).withSignatureDigestAlgorithm(DigestAlgorithm.SHA224).
        withSignatureToken(this.pkcs12SignatureToken).invokeSigning();
    container.addSignature(signature);
    String file = this.getFileBy("bdoc");
    container.saveAsFile(file);
    container = ContainerOpener.open(file);
    Assert.assertEquals("http://www.w3.org/2001/04/xmldsig-more#sha224",
        container.getSignature(0).getSignatureMethod());
  }

  @Test
  public void constructorWithConfigurationParameter() throws Exception {
    Container container = ContainerBuilder.aContainer().
        withConfiguration(Configuration.getInstance()).build();
    Assert.assertEquals("BDOC", container.getType());
  }

  @Test
  @Ignore // Fails on Jenkins - need to verify
  public void createContainerWhenAttachmentNameContainsEstonianCharacters() throws Exception {
    Container container = this.createEmptyContainer();
    String s = "src/test/resources/testFiles/test_o\u0303a\u0308o\u0308u\u0308.txt";
    container.addDataFile(s, "text/plain");
    container.sign(this.pkcs12SignatureToken);
    Assert.assertEquals(1, container.getDataFiles().size());
    TestAssert.assertContainerIsValid(container);
  }

  @Test
  public void containerTypeStringValueForBDOC() throws Exception {
    Assert.assertEquals("application/vnd.etsi.asic-e+zip",
        this.createEmptyContainer(Container.class).getDocumentType().toString());
  }

  @Test
  public void testSigningMultipleFilesInContainer() throws Exception {
    Container container = this.createEmptyContainer();
    container.addDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "1.txt", "text/plain");
    container.addDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "2.txt", "text/plain");
    container.addDataFile(new ByteArrayInputStream(new byte[]{1, 2, 3}), "3.txt", "text/plain");
    TestDataBuilderUtil.signContainer(container);
    String file = this.getFileBy("bdoc");
    container.save(file);
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
    Assert.assertFalse("Data file '" + fileName + "' was not found in the container", true);
  }

}
