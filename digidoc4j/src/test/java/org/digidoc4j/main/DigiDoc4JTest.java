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
import org.digidoc4j.*;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;
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

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

import static com.jcabi.matchers.RegexMatchers.containsPattern;
import static org.digidoc4j.main.DigiDoc4J.isWarning;

public class DigiDoc4JTest extends AbstractTest {

  @Rule
  public final ExpectedSystemExit systemExit = ExpectedSystemExit.none();

  @Rule
  public final SystemOutRule stdOut = new SystemOutRule().enableLog();

  @Test
  public void testComposingAndSigningAndAddingDataToSignFile() {
    this.systemExit.expectSystemExitWithStatus(0);
    String containerFile = this.getFileBy("bdoc");
    String dataToSignFile = this.getFileBy("ser");
    String[] parameters = new String[]{"-in", containerFile,
        "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-dts", dataToSignFile, "text/plain", "-cert", "src/test/resources/testFiles/certs/signout.pem"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertTrue(String.format("No data to sign file <%s>", dataToSignFile), new File(dataToSignFile).exists
        ());
    Assert.assertTrue(String.format("No container file <%s>", containerFile), new File(containerFile).exists());
    String signatureFile = this.getFileBy("sig");
    parameters = new String[]{"-dts", dataToSignFile,
        "-sig", signatureFile, "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertTrue(String.format("No signature file <%s>", signatureFile), new File(signatureFile).exists());
    parameters = new String[]{"-in", containerFile, "-sig", signatureFile,
        "-dts", dataToSignFile};
    DigiDoc4J.main(parameters);
    TestAssert.assertContainerIsValid(this.openContainerBy(Paths.get(containerFile)));
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSAForBDoc() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC",
        "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LTA"};
    TestDigiDoc4JUtil.call(parameters);
    Container container = ContainerOpener.open(file);
    Assert.assertEquals(SignatureProfile.LTA, container.getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSForBDoc() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC",
        "-add", "src/test/resources/testFiles/helper-files/test.txt",
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
    this.clearGlobalMode();
    TestAssert.assertContainerIsValid(container);
  }

  @Test
  public void createsContainerWithSignatureProfileIsBESForBDoc() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC",
        "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "B_BES"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals(SignatureProfile.B_BES, ContainerOpener.open(file).getSignature(0).getProfile());
  }

  @Test
  public void createsECCSignatureWithInvalidEncryptionType() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "src/test/resources/testFiles/p12/ec-digiid.p12", "inno", "-e", "INVALID"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void createsECCSignature() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "src/test/resources/testFiles/p12/MadDogOY.p12", "test", "-e", "ECDSA"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertTrue(ContainerOpener.open(file).validate().isValid());
  }

  @Test
  public void createsContainerWithUnknownSignatureProfile() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC",
        "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "Unknown"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals(SignatureProfile.LT, ContainerOpener.open(file).getSignature(0).getProfile());
  }

  @Test
  public void createNewDDocContainer_throwsException() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString(
                "Not supported: Creating new container is not supported anymore for DDoc!"));
      }

    });
    String file = this.getFileBy("ddoc");
    String[] parameters = new String[]{"-in", file, "-type", "DDOC",
        "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LT_TM"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void addDataFileToDDocContainer_throwsException() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString(
                "Not supported: Adding new data files is not supported anymore for DDoc!"));
      }

    });
    String file = this.getFileBy("ddoc");
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.saveAsFile(file);
    String[] parameters = new String[]{"-in", file, "-type", "DDOC",
            "-add", "src/test/resources/testFiles/helper-files/test.txt",
            "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LT_TM"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void createsContainerWithTypeSettingBDoc() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-type", "BDOC",
        "-add", "src/test/resources/testFiles/helper-files/test.txt",
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
  public void createsContainerWithTypeSettingBasedOnFileExtensionBDoc() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    TestDigiDoc4JUtil.call(parameters);
    Container container = ContainerOpener.open(file);
    Assert.assertEquals("BDOC", container.getType());
  }

  @Test
  public void createsContainerWithTypeSettingBDocIfNoSuitableFileExtensionAndNoType() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    TestDigiDoc4JUtil.call(parameters);
    Assert.assertEquals("BDOC", ContainerOpener.open(file).getType());
  }

  @Test
  public void createsContainerAndSignsIt() throws Exception {
    this.systemExit.expectSystemExitWithStatus(0);
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(parameters);
  }

  @Test
  @Ignore("Requires a physical smart card")
  public void createContainer_andSignIt_withPkcs11() throws Exception {
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
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
    String[] parameters = new String[]{"-in", file,
        "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs11", "/usr/local/lib/opensc-pkcs11.so", "01497", "2",
        "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void createsContainerAndAddsFileWithoutMimeType() throws Exception {
    this.systemExit.expectSystemExitWithStatus(2);
    String file = this.getFileBy("bdoc");
    String[] parameters = new String[]{"-in", file, "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void createMultipleSignedContainers_whereInputDirIsFile_shouldThrowException() throws Exception {
    this.systemExit.expectSystemExitWithStatus(6);
    String[] parameters = new String[]{"-inputDir", this.testFolder.newFile("inputFolder").getPath(),
        "-outputDir", this.testFolder.newFolder("outputFolder").getPath(), "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
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
        this.testFolder.newFolder("outputFolder").getPath(), "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
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
        "src/test/resources/testFiles/p12/signout.p12", "test", "-type", "BDOC"};
    TestDigiDoc4JUtil.call(parameters);
    File folder = new File(outputFolder);
    Assert.assertTrue(folder.exists());
    Assert.assertTrue(folder.isDirectory());
    Assert.assertEquals(2, folder.listFiles().length);
    TestAssert.assertFolderContainsFile(outputFolder, "firstDoc.bdoc");
    TestAssert.assertFolderContainsFile(outputFolder, "secondDoc.bdoc");
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
  public void removeFileFromDDocContainer_throwsException() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString(
                "Not supported: Removing data files is not supported anymore for DDoc!"));
      }

    });
    String file = this.getFileBy("ddoc");
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    container.saveAsFile(file);
    DigiDoc4J.main(new String[]{"-in", file, "-remove", "test.txt"});
  }

  @Test
  public void verifyValidDDoc() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Signature S0 is valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in",
        "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc", "-verify"});
  }

  @Test
  public void verifyDDocWithManifestErrors() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString(
            "Container contains a file named <AdditionalFile.txt> which is not found in the signature file"));
      }

    });
    DigiDoc4J.main(new String[]{"-in",
        "src/test/resources/testFiles/invalid-containers/manifest_validation_error.asice", "-verify"});
  }

  @Test
  public void verboseMode() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString(
            "Opening DDoc container from file: src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc"));
      }

    });
    DigiDoc4J.main(new String[]{"-in",
        "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc", "-verify", "-verbose"});
  }

  @Test
  public void verifyInValidDDoc() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Signature S0 is not valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in",
        "src/test/resources/testFiles/invalid-containers/changed_digidoc_test.ddoc", "-verify"});
  }

  @Test
  public void verifyDDocWithFatalError() throws Exception {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
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
    DigiDoc4J.main(new String[]{"-in",
        "src/test/resources/testFiles/invalid-containers/no_signed_doc_no_signature.ddoc", "-verify"});
  }

  @Test
  public void verifyDDocWithEmptyContainer() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    DigiDoc4J.main(new String[]{"-in",
        "src/test/resources/testFiles/invalid-containers/empty_container_no_signature.ddoc", "-verify"});
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
    String[] parameters = new String[]{"-in",
        "src/test/resources/testFiles/invalid-containers/warning.asice", "-verify", "-warnings"};
    FileUtils.copyFile(
        new File("src/test/resources/testFiles/yaml-configurations/digidoc4j_ForBDocWarningTest.yaml"),
        new File("src/main/resources/digidoc4j.yaml")); // TODO Whaaaaat?
    DigiDoc4J.main(parameters);
  }

  @Test
  public void verifyDDocWithError() {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(),
            StringContains.containsString("ERROR: 13 - Format attribute is mandatory!"));
      }

    });
    DigiDoc4J.main(new String[]{"-in",
        "src/test/resources/testFiles/invalid-containers/empty_container_no_signature.ddoc", "-verify"});
  }

  @Test
  public void verifyDDocWithWarning() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
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
    this.assertExtractingDataFile("src/test/resources/testFiles/valid-containers/one_signature.bdoc",
        "test.txt");
  }

  @Test
  public void extractDataFileFromDdoc() throws Exception {
    this.assertExtractingDataFile("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc",
        "test.txt");
  }

  @Test
  public void extractDataFile_withIncorrectParameters_shouldThrowException() throws Exception {
    this.systemExit.expectSystemExitWithStatus(2);
    DigiDoc4J.main(new String[]{"-in",
        "src/test/resources/testFiles/valid-containers/one_signature.bdoc", "-extract", "test.txt"});
  }

  @Test
  public void extractDataFile_withNonExistingFile_shouldThrowException() throws Exception {
    this.systemExit.expectSystemExitWithStatus(4);
    String[] parameters = new String[]{"-in",
        "src/test/resources/testFiles/valid-containers/one_signature.bdoc", "-extract",
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
        Assert.assertThat(stdOut.getLog(),
            StringContains.containsString("Validation was successful. Container is valid"));
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
    String[] parameters = new String[]{"-in",
        "src/test/resources/prodFiles/valid-containers/valid_prod_bdoc_eid.bdoc", "-v"};
    DigiDoc4J.main(parameters);
  }

  @Test
  public void verifyValidBdocEidWithDss() throws Exception {
    this.setGlobalMode(Configuration.Mode.PROD);
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat("No match", stdOut.getLog(),
            StringContains.containsString("Validation was successful. Container is valid"));
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
    String[] parameters = new String[]{"-in",
        "src/test/resources/prodFiles/valid-containers/valid_edoc2_lv-eId_sha256.edoc", "-v",
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
        Assert.assertThat(stdOut.getLog(),
            StringContains.containsString("Validation was successful. Container is valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in",
        "src/test/resources/prodFiles/valid-containers/valid_edoc2_lv-eId_sha256.edoc", "-v"});
  }

  @Test
  public void verifyValidTestBdoc() throws Exception {
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(),
            StringContains.containsString("Signature id-c0be584463a9dca56c3e9500a3d17e75 is valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in",
        "src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc", "-v"});
  }

  @Test
  public void verifyValidTestBdocWithDss() throws Exception {
    this.systemExit.expectSystemExitWithStatus(0);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(),
            StringContains.containsString("Validation was successful. Container is valid"));
      }

    });
    DigiDoc4J.main(new String[]{"-in",
        "src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc", "-v"});
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
    DigiDoc4J.main(new String[]{"-in",
        "src/test/resources/testFiles/invalid-containers/two_signatures_one_invalid.bdoc", "-v"});
  }

  @Test
  public void verifyInvalidTestBdocWithDss() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {

      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(),
            StringContains.containsString("Validation finished. Container is NOT valid!"));
      }

    });
    DigiDoc4J.main(new String[]{"-in",
        "src/test/resources/testFiles/invalid-containers/two_signatures_one_invalid.bdoc", "-v"});
  }

  @Test
  @Ignore // unstable result
  public void verifyValidBDocUnsafeInteger() throws Exception {
    this.setGlobalMode(Configuration.Mode.PROD);
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(),
            StringContains.containsString("invalid info structure in RSA public key"));
      }
    });
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/prodFiles/valid-containers/InvestorToomas.bdoc", "-verify"});
  }

  @Test
  public void verifyValidBDocUnsafeIntegerSystemParam() throws Exception {
    this.setGlobalMode(Configuration.Mode.PROD);
    this.systemExit.expectSystemExitWithStatus(0);
    System.setProperty(Constant.System.ORG_BOUNCYCASTLE_ASN1_ALLOW_UNSAFE_INTEGER, "true");
    DigiDoc4J.main(new String[]{"-in", "src/test/resources/prodFiles/valid-containers/InvestorToomas.bdoc", "-verify"});
  }

  @Test
  public void verifyBDocFullReport() throws Exception {
    this.systemExit.expectSystemExitWithStatus(1);
    this.systemExit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Type = REVOCATION. BBB_XCV_CCCBB_REV_ANS: " +
            "The certificate chain for revocation data is not trusted, there is no trusted anchor" +
            ""));
        Assert.assertThat(stdOut.getLog(), StringContains.containsString("Block Id: 3a106470aba0437..." +
            " Type = REVOCATION. BBB_XCV_ICSI_ANS: The signature of the certificate is spoiled or it is not possible" +
            " to validate it!"));
      }
    });
    String outputFolder = this.testFolder.newFolder("outputFolder").getPath();
    String[] parameters = new String[]{"-in",
        "src/test/resources/testFiles/invalid-containers/tundmatuocsp.asice", "-v",
        "-r", outputFolder, "-showerrors"};
    DigiDoc4J.main(parameters);
  }

  private void assertExtractingDataFile(String containerPath, String fileToExtract) throws IOException {
    final String outputPath = String.format("%s%s%s",
        this.testFolder.newFolder("outputFolder").getPath(), File.pathSeparator, "output.txt");
    this.systemExit.expectSystemExitWithStatus(0);
    DigiDoc4J.main(new String[]{"-in", containerPath, "-extract", fileToExtract, outputPath});
    TestCommonUtil.sleepInSeconds(1);
    Assert.assertTrue(new File(outputPath).exists());
  }

  @Test
  public void createAndValidateDetachedXades() throws Exception {
    String xadesSignaturePath = "singatures0.xml";

    String[] parameters = new String[]{"-xades", "-digFile", "test.txt",
        "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12",
        "test", "-sigOutputPath", xadesSignaturePath};
    TestDigiDoc4JUtil.call(parameters);

    parameters = new String[]{"-xades", "-digFile", "test.txt",
        "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg", "-sigInputPath", xadesSignaturePath};
    TestDigiDoc4JUtil.call(parameters);

    Assert.assertThat(stdOut.getLog(), containsPattern("Signature id-[a-z0-9]+ is valid"));
    new File(xadesSignaturePath).delete();
  }

  @Test
  public void validateDetachedXades_withWrongDigestFile_shouldFail() throws Exception {
    String[] parameters = new String[]{"-xades", "-digFile", "test.txt",
        "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg", "-sigInputPath",
        "src/test/resources/testFiles/xades/test-bdoc-ts.xml"};
    TestDigiDoc4JUtil.call(parameters);

    Assert.assertThat(stdOut.getLog(), StringContains.containsString("The reference data object(s) is not intact!"));
  }

}
