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

import static org.apache.commons.io.FileUtils.copyFile;
import static org.apache.commons.io.FileUtils.writeStringToFile;
import static org.digidoc4j.Configuration.Mode;
import static org.digidoc4j.Constant.DDOC_CONTAINER_TYPE;
import static org.digidoc4j.main.DigiDoc4J.isWarning;
import static org.digidoc4j.utils.Helper.deleteFile;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.Assertion;
import org.junit.contrib.java.lang.system.ExpectedSystemExit;
import org.junit.contrib.java.lang.system.SystemOutRule;
import org.junit.rules.TemporaryFolder;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;


public class DigiDoc4JTest extends DigiDoc4JTestHelper {

  @Rule
  public final ExpectedSystemExit exit = ExpectedSystemExit.none();

  @Rule
  public final SystemOutRule sout = new SystemOutRule().enableLog();

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();
  private String testBdocContainer;
  private File outputFolder;
  private File inputFolder;
  private String outputDirPath;
  private String inputFolderPath;
  private String tmpDirPath;

  @Before
  public void setUp() throws Exception {
    testBdocContainer = testFolder.newFile("test-container.bdoc").getPath();
    outputFolder = testFolder.newFolder("outputDirectory");
    inputFolder = testFolder.newFolder("inputDirectory");
    outputDirPath = outputFolder.getPath();
    inputFolderPath = inputFolder.getPath();
    tmpDirPath = "src/test/resources/testFiles/tmp/reports/";
    Path dir = Paths.get(tmpDirPath);
    Files.createDirectory(dir);
  }

  @After
  public void cleanUp() throws Exception {
    deleteFile("src/test/resources/testFiles/tmp/digidoc4j.yaml");
    deleteFile("src/test/resources/testFiles/tmp/test1.ddoc");
    deleteFile("src/test/resources/testFiles/tmp/test1.bdoc");
    deleteFile("src/test/resources/testFiles/tmp/test1.test");
    deleteFile("src/test/resources/testFiles/tmp/createsECCSignatureWithInvalidEncryptionType.bdoc");
    deleteFile("src/test/resources/testFiles/tmp/createsECCSignature.bdoc");
    Path dir = Paths.get(tmpDirPath);
    if (Files.exists(dir)) {
      FileUtils.cleanDirectory(new File(dir.toString()));
      Files.deleteIfExists(dir);
    }
  }

  @Test
  public void createsContainerWithTypeSettingDDoc() throws Exception {
    String fileName = tmpDirPath + "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals("DDOC", container.getType());
  }

  @Test
  public void signDDocContainerTwice() throws Exception {
    String fileName = tmpDirPath + "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] signNewContainerParams = new String[]{"-in", fileName, "-type", "DDOC", "-add",
        "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    String[] signExistingContainerParams = new String[]{"-in", fileName, "-pkcs12", "src/test/resources/testFiles/p12/signout.p12",
        "test"};

    callMainWithoutSystemExit(signNewContainerParams);
    callMainWithoutSystemExit(signExistingContainerParams);

    Container container = ContainerOpener.open(fileName);
    assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSAForBDoc() throws Exception {
    String fileName = tmpDirPath + "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LTA"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.LTA, container.getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSForBDoc() throws Exception {
    String fileName = tmpDirPath + "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LT"};

    System.setProperty("digidoc4j.mode", "TEST");
    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.LT, container.getSignature(0).getProfile());
    System.clearProperty("digidoc4j.mode");
  }

  @Test
  public void createsContainerWithSignatureProfileIsBESForBDoc() throws Exception {
    String fileName = tmpDirPath + "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "B_BES"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.B_BES, container.getSignature(0).getProfile());
  }

  @Test(expected = IllegalArgumentException.class)
  public void createsECCSignatureWithInvalidEncryptionType() throws Exception {
    String fileName = tmpDirPath + "createsECCSignatureWithInvalidEncryptionType.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "src/test/resources/testFiles/p12/ec-digiid.p12", "inno", "-e", "INVALID"};

    DigiDoc4J.main(params);
  }

  @Test
  public void createsECCSignature() throws Exception {
    String fileName = tmpDirPath + "createsECCSignature.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "src/test/resources/testFiles/p12/ec-digiid.p12", "inno", "-e", "ECDSA"};

    System.setProperty("digidoc4j.mode", "TEST");
    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void createsContainerWithUnknownSignatureProfile() throws Exception {
    String fileName = tmpDirPath + "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "Unknown"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.LT, container.getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTMForDDoc() throws Exception {
    String fileName = tmpDirPath + "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LT_TM"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.LT_TM, container.getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileTSForDDocReturnsFailureCode() throws Exception {
    exit.expectSystemExitWithStatus(1);

    String fileName = tmpDirPath + "test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LT"};

    DigiDoc4J.main(params);
  }

  @Test
  public void createsContainerWithSignatureProfileTSAForDDocReturnsFailureCode() throws Exception {
    exit.expectSystemExitWithStatus(1);

    String fileName = tmpDirPath + "test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "LTA"};

    DigiDoc4J.main(params);
  }

  @Test
  @Ignore("JDigiDoc by default returns LT_TM profile but should be B_BES profile")
  public void createsContainerWithSignatureProfileBESForDDoc() throws Exception {
    String fileName = tmpDirPath + "test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test", "-profile", "B_BES"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.B_BES, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void createsContainerWithTypeSettingBDoc() throws Exception {
    String fileName = tmpDirPath + "test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals("BDOC", container.getType());
  }

  @Test
  public void defaultDigidoc4jModeIsTest() throws Exception {
    String[] params = new String[]{""};

    callMainWithoutSystemExit(params);
    assertEquals(Mode.TEST.toString(), System.getProperty("digidoc4j.mode"));
  }

  @Test
  public void nonExistingDigidoc4jModeResultsInTest() throws Exception {
    String[] params = new String[]{""};
    System.clearProperty("digidoc4j.mode");

    callMainWithoutSystemExit(params);
    assertEquals(Mode.PROD.toString(), System.getProperty("digidoc4j.mode"));
  }

  @Test
  public void commandLineDigidoc4jModeOverwritesDefault() throws Exception {
    String[] params = new String[]{""};
    System.setProperty("digidoc4j.mode", "PROD");

    callMainWithoutSystemExit(params);
    assertEquals(Mode.PROD.toString(), System.getProperty("digidoc4j.mode"));
  }

  @Test
  public void createsContainerWithTypeSettingBasedOnFileExtensionDDoc() throws Exception {
    String fileName = tmpDirPath + "test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals("DDOC", container.getType());
  }

  @Test
  public void createsContainerWithTypeSettingBasedOnFileExtensionBDoc() throws Exception {
    String fileName = tmpDirPath + "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals("BDOC", container.getType());
  }

  @Test
  public void createsContainerWithTypeSettingBDocIfNoSuitableFileExtensionAndNoType() throws Exception {
    System.setProperty("digidoc4j.mode", "TEST");
    String fileName = tmpDirPath + "test1.test";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals("BDOC", container.getType());
  }

  @Test
  public void createsContainerAndSignsIt() throws Exception {
    exit.expectSystemExitWithStatus(0);
    String fileName = tmpDirPath + "test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));
    String[] params = new String[]{"-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  @Ignore("Requires a physical smart card")
  public void createContainer_andSignIt_withPkcs11() throws Exception {
    Files.deleteIfExists(Paths.get(testBdocContainer));
    String[] params = new String[]{"-in", testBdocContainer, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs11", "/usr/local/lib/opensc-pkcs11.so", "22975", "2"};
    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(testBdocContainer);
    assertEquals(1, container.getDataFiles().size());
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
    assertEquals(1, container.getSignatures().size());
    assertTrue(container.validate().isValid());
  }

  @Test
  public void itShouldNotBePossible_ToSignWithBoth_Pkcs11AndPkcs12() throws Exception {
    exit.expectSystemExitWithStatus(5);
    Files.deleteIfExists(Paths.get(testBdocContainer));
    String[] params = new String[]{"-in", testBdocContainer, "-add", "src/test/resources/testFiles/helper-files/test.txt", "text/plain",
        "-pkcs11", "/usr/local/lib/opensc-pkcs11.so", "01497", "2", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  public void createsContainerAndAddsFileWithoutMimeType() throws Exception {
    exit.expectSystemExitWithStatus(2);
    String fileName = tmpDirPath + "test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));
    String[] params = new String[]{"-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt", "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  public void createMultipleSignedContainers_whereInputDirIsFile_shouldThrowException() throws Exception {
    String inputFolderPath = testFolder.newFile("inputDir").getPath();
    exit.expectSystemExitWithStatus(6);
    String[] params = new String[]{"-inputDir", inputFolderPath, "-outputDir", outputDirPath, "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  public void createMultipleSignedContainers_whereOutputDirIsFile_shouldThrowException() throws Exception {
    String outputDirPath = testFolder.newFile("outputDir").getPath();
    exit.expectSystemExitWithStatus(6);
    String[] params = new String[]{"-inputDir", inputFolderPath, "-outputDir", outputDirPath, "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  public void createMultipleSignedContainers_withEmptyInputDir_shouldDoNothing() throws Exception {
    exit.expectSystemExitWithStatus(0);
    String[] params = new String[]{"-inputDir", inputFolderPath, "-outputDir", outputDirPath, "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  public void createMultipleSignedContainers_withinInputDirectory() throws Exception {
    writeStringToFile(new File(inputFolder, "firstDoc.txt"), "Hello daddy");
    writeStringToFile(new File(inputFolder, "secondDoc.pdf"), "John Matrix");
    writeStringToFile(new File(inputFolder, "thirdDoc.acc"), "Major General Franklin Kirby");

    String[] params = new String[]{"-inputDir", inputFolderPath, "-outputDir", outputDirPath, "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    assertEquals(3, outputFolder.listFiles().length);
    assertContainsFile(outputDirPath, "firstDoc.bdoc");
    assertContainsFile(outputDirPath, "secondDoc.bdoc");
    assertContainsFile(outputDirPath, "thirdDoc.bdoc");
  }

  @Test
  public void createMultipleSignedContainers_withoutOutputDirectory_shouldCreateOutputDir() throws Exception {
    String outputDirPath = new File(inputFolder, "notExistingOutputFolder").getPath();
    writeStringToFile(new File(inputFolder, "firstDoc.txt"), "Hello daddy");
    writeStringToFile(new File(inputFolder, "secondDoc.pdf"), "John Matrix");

    String[] params = new String[]{"-inputDir", inputFolderPath, "-outputDir", outputDirPath, "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test", "-type", "DDOC"};

    callMainWithoutSystemExit(params);

    File outputFolder = new File(outputDirPath);
    assertTrue(outputFolder.exists());
    assertTrue(outputFolder.isDirectory());
    assertEquals(2, outputFolder.listFiles().length);
    String fileName = "firstDoc.ddoc";
    assertContainsFile(outputDirPath, fileName);
    assertContainsFile(outputDirPath, "secondDoc.ddoc");
  }

  @Test
  public void createMultipleSignedContainers_withExistingSavedContainers_shouldThrowException() throws Exception {
    exit.expectSystemExitWithStatus(7);
    writeStringToFile(new File(inputFolder, "firstDoc.txt"), "Hello daddy");
    writeStringToFile(new File(outputFolder, "firstDoc.bdoc"), "John Matrix");

    String[] params = new String[]{"-inputDir", inputFolderPath, "-outputDir", outputDirPath, "-pkcs12",
        "src/test/resources/testFiles/p12/signout.p12", "test"};

    DigiDoc4J.main(params);
  }

  @Test
  public void createSignedContainer_forEachFile_withInputDirectoryAndMimeType() throws Exception {
    writeStringToFile(new File(inputFolder, "firstDoc.txt"), "Hello daddy");
    writeStringToFile(new File(inputFolder, "secondDoc.pdf"), "John Matrix");

    String[] params = new String[]{"-inputDir", inputFolderPath, "-mimeType", "text/xml", "-outputDir", outputDirPath,
        "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(new File(outputDirPath, "firstDoc.bdoc").getPath());
    assertEquals("text/xml", container.getDataFiles().get(0).getMediaType());
    container = ContainerOpener.open(new File(outputDirPath, "secondDoc.bdoc").getPath());
    assertEquals("text/xml", container.getDataFiles().get(0).getMediaType());
  }

  @Test
  public void commandLineInputCausesDigiDoc4JException() throws Exception {
    exit.expectSystemExitWithStatus(1);
    String[] params = new String[]{"-in", "NotFoundFile.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void removeFileFromContainer() throws Exception {
    exit.expectSystemExitWithStatus(0);
    String filename = tmpDirPath + "test1.ddoc";
    Container container = ContainerBuilder.
        aContainer(DDOC_CONTAINER_TYPE).
        build();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    Files.deleteIfExists(Paths.get(filename));
    container.saveAsFile(filename);

    String[] params = new String[]{"-in", filename, "-remove", "test.txt"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyValidDDoc() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Signature S0 is valid"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithManifestErrors() throws Exception {
    exit.expectSystemExitWithStatus(1);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(),containsString(
            "Container contains a file named AdditionalFile.txt which is not found in the signature file"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/invalid-containers/manifest_validation_error.asice", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verboseMode() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString(
            "Opening DDoc container from file: src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc", "-verify", "-verbose"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyInValidDDoc() throws Exception {
    exit.expectSystemExitWithStatus(1);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Signature S0 is not valid"));
      }
    });
    sout.clearLog();
    String[] params = new String[]{"-in", "src/test/resources/testFiles/invalid-containers/changed_digidoc_test.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithFatalError() throws Exception {
    exit.expectSystemExitWithStatus(1);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("ERROR: 75"));
      }
    });
    sout.clearLog();
    String[] params = new String[]{"-in", "src/test/resources/testFiles/invalid-containers/error75.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithoutSignature() throws Exception {
    exit.expectSystemExitWithStatus(1);
    String[] params = new String[]{"-in", "src/test/resources/testFiles/invalid-containers/no_signed_doc_no_signature.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithEmptyContainer() throws Exception {
    exit.expectSystemExitWithStatus(1);
    String[] params = new String[]{"-in", "src/test/resources/testFiles/invalid-containers/empty_container_no_signature.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void showsUsage() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("usage: digidoc4j"));
      }
    });
    DigiDoc4J.main(new String[]{});
  }

  @Test
  @Ignore("Bug report at https://www.pivotaltracker.com/story/show/107563624")
  public void verifyBDocWithWarning() throws IOException {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(),
            containsString("The signer's certificate is not supported by SSCD!"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/invalid-containers/warning.asice", "-verify", "-warnings"};
    copyFile(new File("src/test/resources/testFiles/yaml-configurations/digidoc4j_ForBDocWarningTest.yaml"),
        new File("src/main/resources/digidoc4j.yaml"));
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithError() {
    exit.expectSystemExitWithStatus(1);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("ERROR: 13 - Format attribute is mandatory!"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/invalid-containers/empty_container_no_signature.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithWarning() {
    exit.expectSystemExitWithStatus(1);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString(
            "Warning: ERROR: 176 - X509IssuerName has none or invalid namespace: null"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/invalid-containers/warning.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void testIsWarningWhenNoWarningExists() throws DigiDocException {
    assertFalse(isWarning(SignedDoc.FORMAT_DIGIDOC_XML, new DigiDoc4JException(1, "testError")));
  }

  @Test
  public void testIsNotWarningWhenCodeIsErrIssuerXmlnsAndDocumentFormatIsSkXML() throws DigiDocException {
    assertFalse(isWarning(SignedDoc.FORMAT_SK_XML, new DigiDoc4JException(DigiDocException.ERR_ISSUER_XMLNS,
        "testError")));
  }

  @Test
  public void testIsWarningWhenCodeIsErrIssuerXmlnsAndDocumentFormatIsNotSkXML() throws DigiDocException {
    assertTrue(isWarning(SignedDoc.FORMAT_DIGIDOC_XML, new DigiDoc4JException(DigiDocException.ERR_ISSUER_XMLNS,
        "testError")));
  }

  @Test
  public void testIsWarningWhenWarningIsFound() throws DigiDocException {
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
  public void showVersion() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("DigiDoc4j version"));
      }
    });
    String[] params = {"--version"};
    DigiDoc4J.main(params);
  }

  @Test
  public void extractDataFileFromBdoc() throws Exception {
    testExtractingDataFile("src/test/resources/testFiles/valid-containers/one_signature.bdoc", "test.txt");
  }

  @Test
  public void extractDataFileFromDdoc() throws Exception {
    testExtractingDataFile("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc", "test.txt");
  }

  private void testExtractingDataFile(String containerPath, String fileToExtract) throws IOException {
    final String outputPath = testFolder.newFolder().getPath() + "/output.txt";
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertTrue(new File(outputPath).exists());
      }
    });
    String[] params = new String[]{"-in", containerPath, "-extract", fileToExtract, outputPath};
    DigiDoc4J.main(params);
  }

  @Test
  public void extractDataFile_withIncorrectParameters_shouldThrowException() throws Exception {
    exit.expectSystemExitWithStatus(3);
    String[] params = new String[]{"-in", "src/test/resources/testFiles/valid-containers/one_signature.bdoc", "-extract", "test.txt"};
    DigiDoc4J.main(params);
  }

  @Test
  public void extractDataFile_withNonExistingFile_shouldThrowException() throws Exception {
    final String outputPath = testFolder.newFolder().getPath() + "/output.txt";
    exit.expectSystemExitWithStatus(4);
    String[] params = new String[]{"-in", "src/test/resources/testFiles/valid-containers/one_signature.bdoc", "-extract",
        "notExistingFile.dmc", outputPath};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyContainerWithTstASICS() throws Exception {
    String fileName = "src/test/resources/testFiles/valid-containers/testtimestamp.asics";

    String[] params = new String[]{"-in", fileName, "-v"};
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Container is valid"));
      }
    });
    DigiDoc4J.main(params);
  }

  /* Following test are not independent from each other and can'y be run in suite.

  @Test
  public void verifyValidBdocMid() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Signature S0 is valid"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/valid-containers/valid_prod_bdoc_mid.bdoc", "-v"};
    System.setProperty("digidoc4j.mode", "PROD");
    DigiDoc4J.main(params);
    System.clearProperty("digidoc4j.mode");
  }

  @Test
  public void verifyValidBdocMidWithDss() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Validation was successful. Container is valid"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/valid-containers/valid_prod_bdoc_mid.bdoc", "-v2"};
    System.setProperty("digidoc4j.mode", "PROD");
    DigiDoc4J.main(params);
    System.clearProperty("digidoc4j.mode");
  }

  @Test
  public void verifyValidBdocEid() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Signature S0 is valid"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/valid-containers/valid_prod_bdoc_eid.bdoc", "-v"};
    System.setProperty("digidoc4j.mode", "PROD");
    DigiDoc4J.main(params);
    System.clearProperty("digidoc4j.mode");
  }

  @Test
  public void verifyValidBdocEidWithDss() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Validation was successful. Container is valid"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/valid-containers/valid_prod_bdoc_eid.bdoc", "-v2"};
    System.setProperty("digidoc4j.mode", "PROD");
    DigiDoc4J.main(params);
    System.clearProperty("digidoc4j.mode");
  }

  @Test
  public void verifyValidEdoc() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Signature S1 is valid"));
      }
    });
    Path dir = Paths.get(tmpDirPath + "valid_edoc");
    if (Files.exists(dir)) {
      FileUtils.cleanDirectory(new File(dir.toString()));
      Files.deleteIfExists(dir);
    }
    Files.createDirectory(dir);
    String[] params = new String[]{"-in", "src/test/resources/testFiles/valid-containers/valid_edoc2_lv-eId_sha256.edoc", "-v",
        "-r", dir.toString()};
    System.setProperty("digidoc4j.mode", "PROD");
    DigiDoc4J.main(params);
    System.clearProperty("digidoc4j.mode");
  }

  @Test
  public void verifyValidEdocWithDss() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Validation was successful. Container is valid"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/valid-containers/valid_edoc2_lv-eId_sha256.edoc", "-v2"};
    System.setProperty("digidoc4j.mode", "PROD");
    DigiDoc4J.main(params);
    System.clearProperty("digidoc4j.mode");
  }

  @Test
  public void verifyValidTestBdoc() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Signature id-c0be584463a9dca56c3e9500a3d17e75 is valid"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc", "-v"};
    System.setProperty("digidoc4j.mode", "TEST");
    DigiDoc4J.main(params);
    System.clearProperty("digidoc4j.mode");
  }

  @Test
  public void verifyValidTestBdocWithDss() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Validation was successful. Container is valid"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc", "-v2"};
    System.setProperty("digidoc4j.mode", "TEST");
    DigiDoc4J.main(params);
    System.clearProperty("digidoc4j.mode");
  }

  @Test
  public void verifyInvalidTestBdoc() throws Exception {
    exit.expectSystemExitWithStatus(1);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Signature S1 is not valid"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/invalid-containers/two_signatures_one_invalid.bdoc", "-v"};
    System.setProperty("digidoc4j.mode", "TEST");
    DigiDoc4J.main(params);
    System.clearProperty("digidoc4j.mode");
  }

  @Test
  public void verifyInvalidTestBdocWithDss() throws Exception {
    exit.expectSystemExitWithStatus(1);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Validation finished. Container is NOT valid!"));
      }
    });
    String[] params = new String[]{"-in", "src/test/resources/testFiles/invalid-containers/two_signatures_one_invalid.bdoc", "-v2"};
    System.setProperty("digidoc4j.mode", "TEST");
    DigiDoc4J.main(params);
    System.clearProperty("digidoc4j.mode");
  }
  */

  private void assertContainsFile(String outputDirPath, String fileName) {
    File dir = new File(outputDirPath);
    File file = new File(dir, fileName);
    String errorMsg = "'" + fileName + "' is not present in dir " + Arrays.toString(dir.list());
    assertTrue(errorMsg, file.exists());
  }
}
