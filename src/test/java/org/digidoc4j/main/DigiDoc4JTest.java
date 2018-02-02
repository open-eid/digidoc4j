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

import static org.digidoc4j.main.DigiDoc4J.isWarning;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestCommonUtil;
import org.digidoc4j.test.util.TestDigiDoc4JUtil;
import org.hamcrest.core.StringContains;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.Assertion;
import org.junit.contrib.java.lang.system.ExpectedSystemExit;
import org.junit.contrib.java.lang.system.SystemOutRule;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;

public class DigiDoc4JTest extends AbstractTest {

  @Rule
  public final ExpectedSystemExit systemExit = ExpectedSystemExit.none();

  @Rule
  public final SystemOutRule stdOut = new SystemOutRule().enableLog();

  @Test
  public void createsContainerWithTypeSettingDDoc() {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "DDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals("DDOC", ContainerOpener.open(file).getType());
  }

  @Test
  public void signDDocContainerTwice() {
    String file = this.getFileBy("bdoc");
    String[] signNewContainerParams = new String[]{"-in", file, "-type", "DDOC", "-add",
        "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    String[] signExistingContainerParams = new String[]{"-in", file, "-pkcs12", "src/test/resources/testFiles/p12/signout.p12",
        "test"};
    TestDigiDoc4JUtil.call(signNewContainerParams);
    TestDigiDoc4JUtil.call(signExistingContainerParams);
    Assert.assertEquals(2, ContainerOpener.open(file).getSignatures().size());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSAForBDoc() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LTA"};
    TestDigiDoc4JUtil.call(parameters);
    Container container = ContainerOpener.open(file);
    Assert.assertEquals(SignatureProfile.LTA, container.getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSForBDoc() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LT"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals(SignatureProfile.LT, ContainerOpener.open(file).getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSForAsice() throws Exception {
    String fileName = this.getFileBy("asice");
    String[] params = new String[]{"-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LT"};
    System.setProperty("digidoc4j.mode", "TEST");
    TestDigiDoc4JUtil.call(params);
    Container container = ContainerOpener.open(fileName);
    Assert.assertEquals(SignatureProfile.LT, container.getSignature(0).getProfile());
    System.clearProperty("digidoc4j.mode");
    TestAssert.assertContainerIsValid(container);
  }

  @Test
  public void createsContainerWithSignatureProfileIsBESForBDoc() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "B_BES"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals(SignatureProfile.B_BES, ContainerOpener.open(file).getSignature(0).getProfile());
  }

  @Test(expected = IllegalArgumentException.class)
  public void createsECCSignatureWithInvalidEncryptionType() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "src/test/resources/testFiles/p12/ec-digiid.p12", "inno", "-e", "INVALID"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void createsECCSignature() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "src/test/resources/testFiles/p12/ec-digiid.p12", "inno", "-e", "ECDSA"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertTrue(ContainerOpener.open(file).validate().isValid());
  }

  @Test
  public void createsContainerWithUnknownSignatureProfile() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "Unknown"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals(SignatureProfile.LT, ContainerOpener.open(file).getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTMForDDoc() throws Exception {
    String file = this.getFileBy("ddoc");
    String[] parameters = new String[]{"-in", file, "-type", "DDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LT_TM"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals(SignatureProfile.LT_TM, ContainerOpener.open(file).getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileTSForDDocReturnsFailureCode() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    String file = this.getFileBy("ddoc");
    String[] parameters = new String[]{"-in", file, "-type", "DDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LT"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void createsContainerWithSignatureProfileTSAForDDocReturnsFailureCode() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    String file = this.getFileBy("ddoc");
    String[] parameters = new String[]{"-in", file, "-type", "DDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LTA"};
    DigiDoc4J.main(parameters);
  }

  @Test
  @Ignore("JDigiDoc by default returns LT_TM profile but should be B_BES profile")
  public void createsContainerWithSignatureProfileBESForDDoc() throws Exception {
    String file = this.getFileBy("ddoc");
    String[] parameters = new String[]{"-in", file, "-type", "DDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "B_BES"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals(SignatureProfile.B_BES, ContainerOpener.open(file).getSignatures().get(0).getProfile());
  }

  @Test
  public void createsContainerWithTypeSettingBDoc() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals("BDOC", ContainerOpener.open(file).getType());
  }

  @Test
  public void defaultDigidoc4jModeIsProd() throws Exception {
    this.clearGlobalMode();
    String[] parameters = new String[]{""};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals(Configuration.Mode.PROD.name(), System.getProperty("digidoc4j.mode"));
  }

  @Test
  public void commandLineDigidoc4jModeOverwritesDefault() throws Exception {
    this.setGlobalMode(Configuration.Mode.PROD);
    String[] parameters = new String[]{""};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals(Configuration.Mode.PROD.name(), System.getProperty("digidoc4j.mode"));
  }

  @Test
  public void createsContainerWithTypeSettingBasedOnFileExtensionDDoc() throws Exception {
    String file = this.getFileBy("ddoc");
    String[] parameters = new String[]{"-in", file, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals("DDOC", ContainerOpener.open(file).getType());
  }

  @Test
  public void createsContainerWithTypeSettingBasedOnFileExtensionBDoc() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    TestDigiDoc4JUtil.call(parameters);
    Container container = ContainerOpener.open(file);
    Assert.assertEquals("BDOC", container.getType());
  }

  @Test
  public void createsContainerWithTypeSettingBDocIfNoSuitableFileExtensionAndNoType() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals("BDOC", ContainerOpener.open(file).getType());
  }

  @Test
  public void createsContainerAndSignsIt() throws Exception {
    this.systemExit.expectSystemExitWithStatus(0);
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(parameters);
  }

  @Test
  @Ignore("Requires a physical smart card")
  public void createContainer_andSignIt_withPkcs11() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs11", "/usr/local/lib/opensc-pkcs11.so", "22975", "2"};
    TestDigiDoc4JUtil.call(parameters);
    Container container = ContainerOpener.open(file);
    Assert.assertEquals(1, container.getDataFiles().size());
    Assert.assertEquals("test.txt", container.getDataFiles().get(0).getName());
    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void itShouldNotBePossible_ToSignWithBoth_Pkcs11AndPkcs12() throws Exception {
    this.systemExit.expectSystemExitWithStatus(5);
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs11", "/usr/local/lib/opensc-pkcs11.so", "01497", "2", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void createsContainerAndAddsFileWithoutMimeType() throws Exception {
    this.systemExit.expectSystemExitWithStatus(2);
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-add", "src/test/resources/testFiles/helper-files/test.txt", "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void createMultipleSignedContainers_whereInputDirIsFile_shouldThrowException() throws Exception {
    this.systemExit.expectSystemExitWithStatus(6);
    String[] parameters = new String[]{"-inputDir", this.testFolder.newFile("inputFolder").getPath(), "-outputDir",
        this.testFolder.newFolder("outputFolder").getPath(), "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void createMultipleSignedContainers_whereOutputDirIsFile_shouldThrowException() throws Exception {
    String inputFolder = this.testFolder.newFolder("inputFolder").getPath();
    String outputFolder = this.testFolder.newFile("outputFolder").getPath();
    this.systemExit.expectSystemExitWithStatus(6);
    String[] parameters = new String[]{"-inputDir", inputFolder, "-outputDir", outputFolder, "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void createMultipleSignedContainers_withEmptyInputDir_shouldDoNothing() throws Exception {
    this.systemExit.expectSystemExitWithStatus(0);
    String[] parameters = new String[]{"-inputDir", this.testFolder.newFolder("inputFolder").getPath(), "-outputDir",
        this.testFolder.newFolder("outputFolder").getPath(), "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void createMultipleSignedContainers_withinInputDirectory() throws Exception {
    String inputFolder = this.testFolder.newFolder("inputFolder").getPath();
    String outputFolder = this.testFolder.newFolder("outputFolder").getPath();
    FileUtils.writeStringToFile(new File(inputFolder, "firstDoc.txt"), "Hello daddy");
    FileUtils.writeStringToFile(new File(inputFolder, "secondDoc.pdf"), "John Matrix");
    FileUtils.writeStringToFile(new File(inputFolder, "thirdDoc.acc"), "Major General Franklin Kirby");
    String[] parameters = new String[]{"-inputDir", inputFolder, "-outputDir", outputFolder, "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals(3, new File(outputFolder).listFiles().length);
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
    String[] parameters = new String[]{"-inputDir", inputFolder, "-outputDir", outputFolder, "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test", "-type", "DDOC"};
    TestDigiDoc4JUtil.call(parameters);
    File folder = new File(outputFolder);
    Assert.assertTrue(folder.exists());
    Assert.assertTrue(folder.isDirectory());
    Assert.assertEquals(2, folder.listFiles().length);
    String file = "firstDoc.ddoc";
    TestAssert.assertFolderContainsFile(outputFolder, file);
    TestAssert.assertFolderContainsFile(outputFolder, "secondDoc.ddoc");
  }

  @Test
  public void createMultipleSignedContainers_withExistingSavedContainers_shouldThrowException() throws Exception {
    this.systemExit.expectSystemExitWithStatus(7);
    String inputFolder = this.testFolder.newFolder("inputFolder").getPath();
    String outputFolder = this.testFolder.newFolder("outputFolder").getPath();
    FileUtils.writeStringToFile(new File(inputFolder, "firstDoc.txt"), "Hello daddy");
    FileUtils.writeStringToFile(new File(outputFolder, "firstDoc.bdoc"), "John Matrix");
    String[] parameters = new String[]{"-inputDir", inputFolder, "-outputDir", outputFolder, "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void createSignedContainer_forEachFile_withInputDirectoryAndMimeType() throws Exception {
    String inputFolder = this.testFolder.newFolder().getPath();
    String outputFolder = this.testFolder.newFolder().getPath();
    FileUtils.writeStringToFile(new File(inputFolder, "firstDoc.txt"), "Hello daddy");
    FileUtils.writeStringToFile(new File(inputFolder, "secondDoc.pdf"), "John Matrix");
    String[] parameters = new String[]{"-inputDir", inputFolder, "-mimeType", "text/xml", "-outputDir", outputFolder,
        "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    TestDigiDoc4JUtil.call(parameters);
    Container container = ContainerOpener.open(new File(outputFolder, "firstDoc.bdoc").getPath());
    Assert.assertEquals("text/xml", container.getDataFiles().get(0).getMediaType());
    container = ContainerOpener.open(new File(outputFolder, "secondDoc.bdoc").getPath());
    Assert.assertEquals("text/xml", container.getDataFiles().get(0).getMediaType());
  }

  @Test
  public void commandLineInputCausesDigiDoc4JException() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    DigiDoc4J.main(new String[]{"-in", "NotFoundFile.ddoc", "-verify"});
  }

  @Test
  public void removeFileFromContainer() throws Exception {
    this.systemExit.expectSystemExitWithStatus(0);
    String file = this.getFileBy("ddoc");
    Container container = this.createEmptyContainerBy(Container.DocumentType.DDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    container.saveAsFile(file);
    DigiDoc4J.main(new String[]{"-in", file, "-remove", "test.txt"});
  }

  @Test
  public void verifyValidDDoc() throws Exception {
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Signature S0 is valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc", "-verify"});
  }

  @Test
  public void verifyDDocWithManifestErrors() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString(
            "Container contains a file named AdditionalFile.txt which is not found in the signature file"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/invalid-containers/manifest_validation_error.asice", "-verify"});
  }

  @Test
  public void verboseMode() throws Exception {
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString(
            "Opening DDoc container from file: src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc", "-verify", "-verbose"});
  }

  @Test
  public void verifyInValidDDoc() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Signature S0 is not valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/invalid-containers/changed_digidoc_test.ddoc", "-verify"});
  }

  @Test
  public void verifyDDocWithFatalError() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("ERROR: 75"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/invalid-containers/error75.ddoc", "-verify"});
  }

  @Test
  public void verifyDDocWithoutSignature() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/invalid-containers/no_signed_doc_no_signature.ddoc", "-verify"});
  }

  @Test
  public void verifyDDocWithEmptyContainer() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/invalid-containers/empty_container_no_signature.ddoc", "-verify"});
  }

  @Test
  public void showsUsage() throws Exception {
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("usage: digidoc4j"));
      }

    });
    DigiDoc4J.main(new String[]{});
  }

  @Test
  @Ignore("Bug report at https://www.pivotaltracker.com/story/show/107563624")
  public void verifyBDocWithWarning() throws IOException {
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(),
            StringContains.containsString("The signer's certificate is not supported by SSCD!"));
      }

    });
    String[] parameters = new String[]{"-in", "src/test/resources/testFiles/invalid-containers/warning.asice", "-verify", "-warnings"};
    FileUtils.copyFile(new File("src/test/resources/testFiles/yaml-configurations/digidoc4j_ForBDocWarningTest.yaml"),
        new File("src/main/resources/digidoc4j.yaml")); // TODO Whaaaaat?
    DigiDoc4J.main(parameters);
  }

  @Test
  public void verifyDDocWithError() {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("ERROR: 13 - Format attribute is mandatory!"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/invalid-containers/empty_container_no_signature.ddoc", "-verify"});
  }

  @Test
  public void verifyDDocWithWarning() {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString(
            "Warning: ERROR: 176 - X509IssuerName has none or invalid namespace: null"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/invalid-containers/warning.ddoc", "-verify"});
  }

  @Test
  public void testIsWarningWhenNoWarningExists() throws DigiDocException {
    Assert.assertFalse(isWarning(SignedDoc.FORMAT_DIGIDOC_XML, new DigiDoc4JException(1, "testError")));
  }

  @Test
  public void testIsNotWarningWhenCodeIsErrIssuerXmlnsAndDocumentFormatIsSkXML() throws DigiDocException {
    Assert.assertFalse(isWarning(SignedDoc.FORMAT_SK_XML, new DigiDoc4JException(DigiDocException.ERR_ISSUER_XMLNS,
        "testError")));
  }

  @Test
  public void testIsWarningWhenCodeIsErrIssuerXmlnsAndDocumentFormatIsNotSkXML() throws DigiDocException {
    Assert.assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML, new DigiDoc4JException(DigiDocException.ERR_ISSUER_XMLNS,
        "testError")));
  }

  @Test
  public void testIsWarningWhenWarningIsFound() throws DigiDocException {
    Assert.assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML,
        new DigiDoc4JException(DigiDocException.ERR_DF_INV_HASH_GOOD_ALT_HASH, "test")));
    Assert.assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML,
        new DigiDoc4JException(DigiDocException.ERR_OLD_VER, "test")));
    Assert.assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML,
        new DigiDoc4JException(DigiDocException.ERR_TEST_SIGNATURE, "test")));
    Assert.assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML,
        new DigiDoc4JException(DigiDocException.WARN_WEAK_DIGEST, "test")));
  }

  @Test
  public void showVersion() throws Exception {
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("DigiDoc4j version"));
      }

    });
    String[] parameters = {"--version"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void extractDataFileFromBdoc() throws Exception {
    this.assertExtractingDataFile("src/test/resources/testFiles/valid-containers/one_signature.bdoc", "test.txt");
  }

  @Test
  public void extractDataFileFromDdoc() throws Exception {
    this.assertExtractingDataFile("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc", "test.txt");
  }

  @Test
  public void extractDataFile_withIncorrectParameters_shouldThrowException() throws Exception {
    this.systemExit.expectSystemExitWithStatus(2);
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/valid-containers/one_signature.bdoc", "-extract", "test.txt"});
  }

  @Test
  public void extractDataFile_withNonExistingFile_shouldThrowException() throws Exception {
    this.systemExit.expectSystemExitWithStatus(4);
    String[] parameters = new String[]{"-in", "src/test/resources/testFiles/valid-containers/one_signature.bdoc", "-extract",
        "notExistingFile.dmc", this.testFolder.newFolder("outputFolder").getPath() + "/output.txt"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void verifyContainerWithTstASICS() throws Exception {
    String file = "src/test/resources/testFiles/valid-containers/testtimestamp.asics";
    String[] parameters = new String[]{"-in", file, "-v"};
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Container is valid"));
      }

    });
    DigiDoc4J.main(parameters);
  }

  @Test
  public void verifyValidBdocMid() throws Exception {
    this.setGlobalMode(Configuration.Mode.PROD);
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Signature S0 is valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/prodFiles/valid-containers/valid_prod_bdoc_mid.bdoc", "-v"});
  }

  @Test
  public void verifyValidBdocMidWithDss() throws Exception {
    this.setGlobalMode(Configuration.Mode.PROD);
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Validation was successful. Container is valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/prodFiles/valid-containers/valid_prod_bdoc_mid.bdoc", "-v"});
  }

  @Test
  public void verifyValidBdocEid() throws Exception {
    this.setGlobalMode(Configuration.Mode.PROD);
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Signature S0 is valid"));
      }

    });
    String[] parameters = new String[]{"-in", "src/test/resources/prodFiles/valid-containers/valid_prod_bdoc_eid.bdoc", "-v"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void verifyValidBdocEidWithDss() throws Exception {
    this.setGlobalMode(Configuration.Mode.PROD);
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat("No match", stdOut.getLog(), StringContains.containsString("Validation was successful. Container is valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/prodFiles/valid-containers/valid_prod_bdoc_eid.bdoc", "-v"});
  }

  @Test
  public void verifyValidEdoc() throws Exception {
    this.setGlobalMode(Configuration.Mode.PROD);
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Signature S1 is valid"));
      }

    });
    String outputFolder = this.testFolder.newFolder("outputFolder").getPath();
    String[] parameters = new String[]{"-in", "src/test/resources/prodFiles/valid-containers/valid_edoc2_lv-eId_sha256.edoc", "-v",
        "-r", outputFolder};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void verifyValidEdocWithDss() throws Exception {
    this.setGlobalMode(Configuration.Mode.PROD);
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Validation was successful. Container is valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/prodFiles/valid-containers/valid_edoc2_lv-eId_sha256.edoc", "-v"});
  }

  @Test
  public void verifyValidTestBdoc() throws Exception {
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Signature id-c0be584463a9dca56c3e9500a3d17e75 is valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc", "-v"});
  }

  @Test
  public void verifyValidTestBdocWithDss() throws Exception {
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Validation was successful. Container is valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc", "-v"});
  }

  @Test
  public void verifyInvalidTestBdoc() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Signature S1 is not valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/invalid-containers/two_signatures_one_invalid.bdoc", "-v"});
  }

  @Test
  public void verifyInvalidTestBdocWithDss() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Validation finished. Container is NOT valid!"));
      }

    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/testFiles/invalid-containers/two_signatures_one_invalid.bdoc", "-v"});
  }

  private void assertExtractingDataFile(String containerPath, String fileToExtract) throws IOException {
    final String outputPath = String.format("%s%s%s", this.testFolder.newFolder("outputFolder").getPath(), File.pathSeparator, "output.txt");
    this.systemExit.expectSystemExitWithStatus(0);
    DigiDoc4J.main(new String[]{"-in", containerPath, "-extract", fileToExtract, outputPath});
    TestCommonUtil.sleepInSeconds(1);
    Assert.assertTrue(new File(outputPath).exists());
  }

}
