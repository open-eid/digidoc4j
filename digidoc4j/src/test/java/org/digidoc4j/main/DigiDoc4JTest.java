/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.main;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestCommonUtil;
import org.digidoc4j.test.util.TestSigningUtil;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.SystemOutRule;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

import static org.digidoc4j.main.DigiDoc4J.isWarning;
import static org.digidoc4j.main.TestDigiDoc4JUtil.invokeDigiDoc4jAndReturnExitStatus;
import static org.digidoc4j.test.matcher.ContainsPattern.containsPattern;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class DigiDoc4JTest extends AbstractTest {

  @Rule
  public final SystemOutRule stdOut = new SystemOutRule().enableLog();

  @Test
  public void testComposingAndSigningAndAddingDataToSignFile() {
    String containerFile = this.getFileBy("bdoc");
    String dataToSignFile = this.getFileBy("ser");
    String[] parameters = new String[]{"-in", containerFile,
        "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-dts", dataToSignFile, "text/plain", "-cert", "src/test/resources/testFiles/certs/sign_RSA_from_TEST_of_ESTEIDSK2015.pem"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    assertTrue(String.format("No data to sign file <%s>", dataToSignFile), new File(dataToSignFile).exists());
    assertTrue(String.format("No container file <%s>", containerFile), new File(containerFile).exists());
    String signatureFile = this.getFileBy("sig");
    parameters = new String[]{"-dts", dataToSignFile,
        "-sig", signatureFile, "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    assertTrue(String.format("No signature file <%s>", signatureFile), new File(signatureFile).exists());
    parameters = new String[]{"-in", containerFile, "-sig", signatureFile,
        "-dts", dataToSignFile};
    caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    TestAssert.assertContainerIsValid(this.openContainerBy(Paths.get(containerFile)));
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSAForBDoc() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC",
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD,
        "-profile", "LTA"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    Container container = ContainerOpener.open(file);
    assertEquals(SignatureProfile.LTA, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSForBDoc() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC",
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD,
        "-profile", "LT"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    assertEquals(SignatureProfile.LT, ContainerOpener.open(file).getSignatures().get(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSForAsice() {
    String fileName = this.getFileBy("asice");
    String[] params = new String[]{"-in", fileName,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD,
        "-profile", "LT"};
    System.setProperty("digidoc4j.mode", "TEST");
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(params);
    assertEquals(0, caughtExitStatus);
    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.LT, container.getSignatures().get(0).getProfile());
    this.clearGlobalMode();
    TestAssert.assertContainerIsValid(container);
  }

  @Test
  public void createsContainerWithSignatureProfileIsTForAsice() {
    String fileName = this.getFileBy("asice");
    String[] params = new String[]{"-in", fileName,
            "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
            "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD,
            "-profile", "T"};
    System.setProperty("digidoc4j.mode", "TEST");
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(params);
    assertEquals(0, caughtExitStatus);
    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.T, container.getSignatures().get(0).getProfile());
    this.clearGlobalMode();
    container.validate();
    assertThat(stdOut.getLog(), containsString("The certificate validation is not conclusive!"));
    assertThat(stdOut.getLog(), containsString("No revocation data found for the certificate!"));
  }

  @Test
  public void createsContainerWithSignatureProfileIsBESForBDoc() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC",
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD,
        "-profile", "B_BES"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    assertEquals(SignatureProfile.B_BES, ContainerOpener.open(file).getSignatures().get(0).getProfile());
  }

  @Test
  public void createsECCSignatureWithInvalidEncryptionType() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "src/test/resources/testFiles/p12/ec-digiid.p12", "inno", "-e", "INVALID"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(1, caughtExitStatus);
  }

  @Test
  public void createsECCSignature() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "src/test/resources/testFiles/p12/sign_ECC_from_TEST_of_ESTEIDSK2015.p12", "1234", "-e", "ECDSA"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    assertTrue(ContainerOpener.open(file).validate().isValid());
  }

  @Test
  public void createsContainerWithUnknownSignatureProfile() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC",
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD,
        "-profile", "Unknown"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    assertEquals(SignatureProfile.LT, ContainerOpener.open(file).getSignatures().get(0).getProfile());
  }

  @Test
  public void createNewDDocContainer_throwsException() {
    String file = this.getFileBy("ddoc");
    String[] parameters = new String[]{"-in", file, "-type", "DDOC",
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD,
        "-profile", "LT_TM"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString(
            "Not supported: Creating new container is not supported anymore for DDoc!"));
  }

  @Test
  public void addDataFileToDDocContainer_throwsException() {
    String file = this.getFileBy("ddoc");
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.saveAsFile(file);
    String[] parameters = new String[]{"-in", file, "-type", "DDOC",
            "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
            "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD,
            "-profile", "LT_TM"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString(
            "Not supported: Adding new data files is not supported anymore for DDoc!"));
  }

  @Test
  public void createsContainerWithTypeSettingBDoc() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC",
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    Container container = ContainerOpener.open(file);
    assertAsicEContainer(container);
  }

  @Test
  public void defaultDigidoc4jModeIsProd() {
    this.clearGlobalMode();
    String[] parameters = new String[]{""};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    assertEquals(Configuration.Mode.PROD.name(), System.getProperty("digidoc4j.mode"));
  }

  @Test
  public void commandLineDigidoc4jModeOverwritesDefault() {
    this.setGlobalMode(Configuration.Mode.PROD);
    String[] parameters = new String[]{""};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    assertEquals(Configuration.Mode.PROD.name(), System.getProperty("digidoc4j.mode"));
  }

  @Test
  public void createsContainerWithTypeSettingBasedOnFileExtensionBDoc() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    Container container = ContainerOpener.open(file);
    assertAsicEContainer(container);
  }

  @Test
  public void createsContainerWithTypeSettingBDocIfNoSuitableFileExtensionAndNoType() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    Container container = ContainerOpener.open(file);
    assertAsicEContainer(container);
  }

  @Test
  public void createsContainerAndSignsIt() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
  }

  @Test
  @Ignore("Requires a physical smart card")
  public void createContainer_andSignIt_withPkcs11() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs11", "/usr/local/lib/opensc-pkcs11.so", "22975", "2"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    Container container = ContainerOpener.open(file);
    assertEquals(1, container.getDataFiles().size());
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
    assertEquals(1, container.getSignatures().size());
    assertTrue(container.validate().isValid());
  }

  @Test
  public void itShouldNotBePossible_ToSignWithBoth_Pkcs11AndPkcs12() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs11", "/usr/local/lib/opensc-pkcs11.so", "01497", "2",
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(5, caughtExitStatus);
  }

  @Test
  public void createsContainerAndAddsFileWithoutMimeType() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(2, caughtExitStatus);
  }

  @Test
  public void createMultipleSignedContainers_whereInputDirIsFile_shouldThrowException() throws Exception {
    String[] parameters = new String[]{"-inputDir", this.testFolder.newFile("inputFolder").getPath(),
        "-outputDir", this.testFolder.newFolder("outputFolder").getPath(),
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(6, caughtExitStatus);
  }

  @Test
  public void createMultipleSignedContainers_whereOutputDirIsFile_shouldThrowException() throws Exception {
    String inputFolder = this.testFolder.newFolder("inputFolder").getPath();
    String outputFolder = this.testFolder.newFile("outputFolder").getPath();
    String[] parameters = new String[]{"-inputDir", inputFolder, "-outputDir", outputFolder,
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(6, caughtExitStatus);
  }

  @Test
  public void createMultipleSignedContainers_withEmptyInputDir_shouldDoNothing() throws Exception {
    String[] parameters = new String[]{"-inputDir", this.testFolder.newFolder("inputFolder").getPath(),
        "-outputDir", this.testFolder.newFolder("outputFolder").getPath(),
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
  }

  @Test
  public void createMultipleSignedContainers_withinInputDirectory() throws Exception {
    String inputFolder = this.testFolder.newFolder("inputFolder").getPath();
    String outputFolder = this.testFolder.newFolder("outputFolder").getPath();
    FileUtils.writeStringToFile(new File(inputFolder, "firstDoc.txt"), "Hello daddy");
    FileUtils.writeStringToFile(new File(inputFolder, "secondDoc.pdf"), "John Matrix");
    FileUtils.writeStringToFile(new File(inputFolder, "thirdDoc.acc"), "Major General Franklin Kirby");
    String[] parameters = new String[]{"-inputDir", inputFolder, "-outputDir", outputFolder,
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    assertEquals(3, new File(outputFolder).listFiles().length);
    TestAssert.assertFolderContainsFile(outputFolder, "firstDoc.bdoc");
    TestAssert.assertFolderContainsFile(outputFolder, "secondDoc.bdoc");
    TestAssert.assertFolderContainsFile(outputFolder, "thirdDoc.bdoc");
  }

  @Test
  public void createMultipleSignedContainers_withoutOutputDirectory_shouldCreateOutputDir() throws Exception {
    String inputFolder = this.testFolder.newFolder("inputFolder").getPath();
    String outputFolder = new File(inputFolder, "notExistingOutputFolder").getPath();
    FileUtils.writeStringToFile(new File(inputFolder, "firstDoc.txt"), "Hello daddy");
    FileUtils.writeStringToFile(new File(inputFolder, "secondDoc.pdf"), "John Matrix");
    String[] parameters = new String[]{"-inputDir", inputFolder, "-outputDir", outputFolder,
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD,
        "-type", "BDOC"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    File folder = new File(outputFolder);
    assertTrue(folder.exists());
    assertTrue(folder.isDirectory());
    assertEquals(2, folder.listFiles().length);
    TestAssert.assertFolderContainsFile(outputFolder, "firstDoc.bdoc");
    TestAssert.assertFolderContainsFile(outputFolder, "secondDoc.bdoc");
  }

  @Test
  public void createMultipleSignedContainers_withExistingSavedContainers_shouldThrowException() throws Exception {
    String inputFolder = this.testFolder.newFolder("inputFolder").getPath();
    String outputFolder = this.testFolder.newFolder("outputFolder").getPath();
    FileUtils.writeStringToFile(new File(inputFolder, "firstDoc.txt"), "Hello daddy");
    FileUtils.writeStringToFile(new File(outputFolder, "firstDoc.bdoc"), "John Matrix");
    String[] parameters = new String[]{"-inputDir", inputFolder, "-outputDir", outputFolder,
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(7, caughtExitStatus);
  }

  @Test
  public void createSignedContainer_forEachFile_withInputDirectoryAndMimeType() throws Exception {
    String inputFolder = this.testFolder.newFolder().getPath();
    String outputFolder = this.testFolder.newFolder().getPath();
    FileUtils.writeStringToFile(new File(inputFolder, "firstDoc.txt"), "Hello daddy");
    FileUtils.writeStringToFile(new File(inputFolder, "secondDoc.pdf"), "John Matrix");
    String[] parameters = new String[]{"-inputDir", inputFolder, "-mimeType", "text/xml", "-outputDir", outputFolder,
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    Container container = ContainerOpener.open(new File(outputFolder, "firstDoc.bdoc").getPath());
    assertEquals("text/xml", container.getDataFiles().get(0).getMediaType());
    container = ContainerOpener.open(new File(outputFolder, "secondDoc.bdoc").getPath());
    assertEquals("text/xml", container.getDataFiles().get(0).getMediaType());
  }

  @Test
  public void commandLineInputCausesDigiDoc4JException() {
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in", "NotFoundFile.ddoc", "-verify");
    assertEquals(1, caughtExitStatus);
  }

  @Test
  public void removeFileFromDDocContainer_throwsException() {
    String file = this.getFileBy("ddoc");
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.saveAsFile(file);
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in", file, "-remove", "test.txt");
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString(
            "Not supported: Removing data files is not supported anymore for DDoc!"));
  }

  @Test
  public void verifyValidDDoc() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc", "-verify");
    assertEquals(0, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString("Signature S0 is valid"));
  }

  @Test
  public void verifyTSignatureProfileAsice() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/valid-containers/signature-level-T.asice", "-verify");
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString("Signature has 2 validation errors and 1 warnings"));
    assertThat(stdOut.getLog(), containsString("The certificate validation is not conclusive!"));
    assertThat(stdOut.getLog(), containsString("No revocation data found for the certificate!"));
    assertThat(stdOut.getLog(), containsString("The signature/seal is an INDETERMINATE AdES digital signature!"));
  }

  @Test
  public void verifyDDocWithManifestErrors() {
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/invalid-containers/manifest_validation_error.asice", "-verify");
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString(
            "Container contains a file named <AdditionalFile.txt> which is not found in the signature file"));
  }

  @Test
  public void verboseMode() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc", "-verify", "-verbose");
    assertEquals(0, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString(
            "Opening DDoc container from file: src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc"));
  }

  @Test
  public void verifyInValidDDoc() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/invalid-containers/changed_digidoc_test.ddoc", "-verify");
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString("Signature S0 is not valid"));
  }

  @Test
  public void verifyDDocWithFatalError() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/invalid-containers/error75.ddoc", "-verify");
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString("ERROR: 75"));
  }

  @Test
  public void verifyDDocWithoutSignature() {
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/invalid-containers/no_signed_doc_no_signature.ddoc", "-verify");
    assertEquals(1, caughtExitStatus);
  }

  @Test
  public void verifyDDocWithEmptyContainer() {
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/invalid-containers/empty_container_no_signature.ddoc", "-verify");
    assertEquals(1, caughtExitStatus);
  }

  @Test
  public void showsUsage() {
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus();
    assertEquals(0, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString("usage: digidoc4j"));
  }

  @Test
  @Ignore("Bug report at https://www.pivotaltracker.com/story/show/107563624")
  public void verifyBDocWithWarning() throws IOException {
    String[] parameters = new String[]{"-in",
        "src/test/resources/testFiles/invalid-containers/warning.asice", "-verify", "-warnings"};
    FileUtils.copyFile(
        new File("src/test/resources/testFiles/yaml-configurations/digidoc4j_ForBDocWarningTest.yaml"),
        new File("src/main/resources/digidoc4j.yaml")); // TODO Whaaaaat?
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString("The signer's certificate is not supported by SSCD!"));
  }

  @Test
  public void verifyDDocWithError() {
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/invalid-containers/empty_container_no_signature.ddoc", "-verify");
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(),
            containsString("ERROR: 13 - Format attribute is mandatory!"));
  }

  @Test
  public void verifyDDocWithWarning() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/invalid-containers/warning.ddoc", "-verify");
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString(
            "Warning: ERROR: 176 - X509IssuerName has none or invalid namespace: null"));
  }

  @Test
  public void testIsWarningWhenNoWarningExists() {
    Assert.assertFalse(isWarning(SignedDoc.FORMAT_DIGIDOC_XML, new DigiDoc4JException(1, "testError")));
  }

  @Test
  public void testIsNotWarningWhenCodeIsErrIssuerXmlnsAndDocumentFormatIsSkXML() {
    Assert.assertFalse(isWarning(SignedDoc.FORMAT_SK_XML, new DigiDoc4JException(DigiDocException.ERR_ISSUER_XMLNS,
        "testError")));
  }

  @Test
  public void testIsWarningWhenCodeIsErrIssuerXmlnsAndDocumentFormatIsNotSkXML() {
    assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML, new DigiDoc4JException(DigiDocException.ERR_ISSUER_XMLNS,
        "testError")));
  }

  @Test
  public void testIsWarningWhenWarningIsFound() {
    assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML,
        new DigiDoc4JException(DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH, "test")));
    assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML,
        new DigiDoc4JException(DigiDocException.ERR_OLD_VER, "test")));
    assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML,
        new DigiDoc4JException(DigiDocException.ERR_TEST_SIGNATURE, "test")));
    assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML,
        new DigiDoc4JException(DigiDocException.WARN_WEAK_DIGEST, "test")));
  }

  @Test
  public void showVersion() {
    String[] parameters = {"--version"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString("DigiDoc4j version"));
  }

  @Test
  public void extractDataFileFromBdoc() throws Exception {
    this.assertExtractingDataFile("src/test/resources/testFiles/valid-containers/one_signature.bdoc",
        "test.txt");
  }

  @Test
  public void extractDataFileFromDdoc() throws Exception {
    this.assertExtractingDataFile("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc",
        "test.txt");
  }

  @Test
  public void extractDataFile_withIncorrectParameters_shouldThrowException() {
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/valid-containers/one_signature.bdoc", "-extract", "test.txt");
    assertEquals(2, caughtExitStatus);
  }

  @Test
  public void extractDataFile_withNonExistingFile_shouldThrowException() throws Exception {
    String[] parameters = new String[]{"-in",
        "src/test/resources/testFiles/valid-containers/one_signature.bdoc", "-extract",
        "notExistingFile.dmc", this.testFolder.newFolder("outputFolder").getPath() + "/output.txt"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(4, caughtExitStatus);
  }

  @Test
  public void verifyContainerWithTstASICS() {
    String file = "src/test/resources/testFiles/valid-containers/testtimestamp.asics";
    String[] parameters = new String[]{"-in", file, "-v"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString("Container is valid"));
  }

  @Test
  public void verifyValidBdocMid() {
    this.setGlobalMode(Configuration.Mode.PROD);
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/prodFiles/valid-containers/valid_prod_bdoc_mid.bdoc", "-v");
    assertEquals(0, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString("Signature S0 is valid"));
  }

  @Test
  public void verifyValidBdocMidWithDss() {
    this.setGlobalMode(Configuration.Mode.PROD);
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/prodFiles/valid-containers/valid_prod_bdoc_mid.bdoc", "-v");
    assertEquals(0, caughtExitStatus);
    assertThat(stdOut.getLog(),
            containsString("Validation was successful. Container is valid"));
  }

  @Test
  public void verifyValidBdocEid() {
    this.setGlobalMode(Configuration.Mode.PROD);
    String[] parameters = new String[]{"-in",
        "src/test/resources/prodFiles/valid-containers/valid_prod_bdoc_eid.bdoc", "-v"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);
    assertThat(stdOut.getLog(),
            containsString("Signature S0 is valid"));
  }

  @Test
  public void verifyValidBdocEidWithDss() {
    this.setGlobalMode(Configuration.Mode.PROD);
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/prodFiles/valid-containers/valid_prod_bdoc_eid.bdoc", "-v");
    assertEquals(0, caughtExitStatus);
    assertThat(stdOut.getLog(),
            containsString("Validation was successful. Container is valid"));
  }

  @Test
  public void verifyEdoc() throws Exception {
    this.setGlobalMode(Configuration.Mode.PROD);
    String outputFolder = this.testFolder.newFolder("outputFolder").getPath();
    String[] parameters = new String[]{"-in",
        "src/test/resources/prodFiles/invalid-containers/edoc2_lv-eId_sha256.edoc", "-v",
        "-r", outputFolder};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString("OCSP response production time is before timestamp time"));
    assertThat(stdOut.getLog(), containsString("Error: (Signature ID: S1) - Timestamp time is after OCSP response production time"));
    assertThat(stdOut.getLog(), containsString("Error: (Signature ID: S1) - The certificate is not related to a TSA/QTST!"));
    assertThat(stdOut.getLog(), containsString("Signature has 2 validation errors"));
    assertThat(stdOut.getLog(), containsString("Signature S1 is not valid"));
  }

  @Test
  public void verifyEdocWithDss() {
    this.setGlobalMode(Configuration.Mode.PROD);
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/prodFiles/invalid-containers/edoc2_lv-eId_sha256.edoc", "-v");
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString("OCSP response production time is before timestamp time"));
    assertThat(stdOut.getLog(), containsString("Error: (Signature ID: S1) - Timestamp time is after OCSP response production time"));
    assertThat(stdOut.getLog(), containsString("Error: (Signature ID: S1) - The certificate is not related to a TSA/QTST!"));
    assertThat(stdOut.getLog(), containsString("Signature has 2 validation errors"));
    assertThat(stdOut.getLog(), containsString("Validation finished. Container is NOT valid!"));
  }

  @Test
  public void verifyValidTestBdoc() {
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc", "-v");
    assertEquals(0, caughtExitStatus);
    assertThat(stdOut.getLog(),
            containsString("Signature id-c0be584463a9dca56c3e9500a3d17e75 is valid"));
  }

  @Test
  public void verifyValidTestBdocWithDss() {
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc", "-v");
    assertEquals(0, caughtExitStatus);
    assertThat(stdOut.getLog(),
            containsString("Validation was successful. Container is valid"));
  }

  @Test
  public void verifyInvalidTestBdoc() {
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/invalid-containers/two_signatures_one_invalid.bdoc", "-v");
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(),
            containsString("Signature S1 is not valid"));
  }

  @Test
  public void verifyInvalidTestBdocWithDss() {
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/testFiles/invalid-containers/two_signatures_one_invalid.bdoc", "-v");
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(),
            containsString("Validation finished. Container is NOT valid!"));
  }

  @Test
  @Ignore // unstable result
  public void verifyValidBDocUnsafeInteger() {
    this.setGlobalMode(Configuration.Mode.PROD);
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/prodFiles/valid-containers/InvestorToomas.bdoc", "-verify");
    assertEquals(0, caughtExitStatus);
  }

  @Test
  public void verifyValidBDocUnsafeIntegerSystemParam() {
    this.setGlobalMode(Configuration.Mode.PROD);
    System.setProperty(Constant.System.ORG_BOUNCYCASTLE_ASN1_ALLOW_UNSAFE_INTEGER, "true");
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in",
            "src/test/resources/prodFiles/valid-containers/InvestorToomas.bdoc", "-verify");
    assertEquals(0, caughtExitStatus);
  }

  @Test
  public void verifyBDocFullReport() throws Exception {
    String outputFolder = this.testFolder.newFolder("outputFolder").getPath();
    String[] parameters = new String[]{"-in",
        "src/test/resources/testFiles/invalid-containers/tundmatuocsp.asice", "-v",
        "-r", outputFolder, "-showerrors"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(1, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString(
            "The certificate chain for revocation data is not trusted, it does not contain a trust anchor"));
  }

  private void assertExtractingDataFile(String containerPath, String fileToExtract) throws IOException {
    final String outputPath = String.format("%s%s%s",
        this.testFolder.newFolder("outputFolder").getPath(), File.pathSeparator, "output.txt");
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus("-in", containerPath, "-extract", fileToExtract, outputPath);
    assertEquals(0, caughtExitStatus);
    TestCommonUtil.sleepInSeconds(1);
    assertTrue(new File(outputPath).exists());
  }

  @Test
  public void createAndValidateDetachedXades() {
    String xadesSignaturePath = "singatures0.xml";

    String[] parameters = new String[]{"-xades",
        "-digFile", "test.txt", "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg", "text/plain",
        "-pkcs12", TestSigningUtil.TEST_PKI_CONTAINER, TestSigningUtil.TEST_PKI_CONTAINER_PASSWORD,
        "-sigOutputPath", xadesSignaturePath};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);

    parameters = new String[]{"-xades", "-digFile", "test.txt",
        "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg", "text/plain","-sigInputPath", xadesSignaturePath};
    caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);
    assertEquals(0, caughtExitStatus);

    assertThat(stdOut.getLog(), containsPattern("Signature id-[a-z0-9]+ is valid"));
    new File(xadesSignaturePath).delete();
  }

  @Test
  public void validateDetachedXades_withWrongDigestFile_shouldFail() {
    String[] parameters = new String[]{"-xades", "-digFile", "test.txt",
        "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg", "text/plain", "-sigInputPath",
        "src/test/resources/testFiles/xades/test-bdoc-ts.xml"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);

    assertEquals(0, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString("The reference data object is not intact!"));
  }

  @Test
  public void validateDetachedXades_mimeTypeNotSet_shouldFail() {
    String[] parameters = new String[]{"-xades", "-digFile", "test.txt",
            "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg", "-sigInputPath",
            "src/test/resources/testFiles/xades/test-bdoc-ts.xml"};
    int caughtExitStatus = invokeDigiDoc4jAndReturnExitStatus(parameters);

    assertEquals(2, caughtExitStatus);
    assertThat(stdOut.getLog(), containsString("Problem with given parameters"));
  }
}
