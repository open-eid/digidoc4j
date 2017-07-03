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

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;

import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.Assertion;
import org.junit.contrib.java.lang.system.ExpectedSystemExit;
import org.junit.contrib.java.lang.system.StandardOutputStreamLog;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Permission;
import java.util.Arrays;

import static org.apache.commons.io.FileUtils.copyFile;
import static org.apache.commons.io.FileUtils.writeStringToFile;
import static org.digidoc4j.Configuration.Mode;

import org.digidoc4j.SignatureProfile;
import org.junit.rules.TemporaryFolder;

import static org.digidoc4j.ContainerBuilder.DDOC_CONTAINER_TYPE;
import static org.digidoc4j.main.DigiDoc4J.isWarning;
import static org.digidoc4j.utils.Helper.deleteFile;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.*;


public class DigiDoc4JTest extends DigiDoc4JTestHelper {

  @Rule
  public final ExpectedSystemExit exit = ExpectedSystemExit.none();

  @Rule
  public final StandardOutputStreamLog sout = new StandardOutputStreamLog();

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();
  private String testBdocContainer;
  private File outputFolder;
  private File inputFolder;
  private String outputDirPath;
  private String inputFolderPath;

  @Before
  public void setUp() throws Exception {
    testBdocContainer = testFolder.newFile("test-container.bdoc").getPath();
    outputFolder = testFolder.newFolder("outputDirectory");
    inputFolder = testFolder.newFolder("inputDirectory");
    outputDirPath = outputFolder.getPath();
    inputFolderPath = inputFolder.getPath();
  }

  @After
  public void cleanUp() throws Exception {
    deleteFile("testFiles/tmp/digidoc4j.yaml");
    deleteFile("testFiles/tmp/test1.ddoc");
    deleteFile("testFiles/tmp/test1.bdoc");
    deleteFile("testFiles/tmp/test1.test");
    deleteFile("testFiles/tmp/createsECCSignatureWithInvalidEncryptionType.bdoc");
    deleteFile("testFiles/tmp/createsECCSignature.bdoc");
  }

  @Test
  public void createsContainerWithTypeSettingDDoc() throws Exception {
    String fileName = "testFiles/tmp/test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals("DDOC", container.getType());
  }

  @Test
  public void signDDocContainerTwice() throws Exception {
    String fileName = "testFiles/tmp/test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] signNewContainerParams = new String[]{"-in", fileName, "-type", "DDOC", "-add", "testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "testFiles/p12/signout.p12", "test"};
    String[] signExistingContainerParams = new String[]{"-in", fileName, "-pkcs12", "testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(signNewContainerParams);
    callMainWithoutSystemExit(signExistingContainerParams);

    Container container = ContainerOpener.open(fileName);
    assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSAForBDoc() throws Exception {
    String fileName = "testFiles/tmp/test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "testFiles/p12/signout.p12", "test", "-profile", "LTA"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.LTA, container.getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSForBDoc() throws Exception {
    String fileName = "testFiles/tmp/test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "testFiles/p12/signout.p12", "test", "-profile", "LT"};

    System.setProperty("digidoc4j.mode", "TEST");
    callMainWithoutSystemExit(params);


    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.LT, container.getSignature(0).getProfile());
    System.clearProperty("digidoc4j.mode");
  }


  @Test
  public void createsContainerWithSignatureProfileIsBESForBDoc() throws Exception {
    String fileName = "testFiles/tmp/test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "testFiles/p12/signout.p12", "test", "-profile", "B_BES"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.B_BES, container.getSignature(0).getProfile());
  }

  @Test (expected = IllegalArgumentException.class)
  public void createsECCSignatureWithInvalidEncryptionType() throws Exception {
    String fileName = "testFiles/tmp/createsECCSignatureWithInvalidEncryptionType.bdoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-add", "testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "testFiles/p12/ec-digiid.p12", "inno", "-e", "INVALID"};

    DigiDoc4J.main(params);
  }

  @Test
  public void createsECCSignature() throws Exception {
    String fileName = "testFiles/tmp/createsECCSignature.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "testFiles/p12/ec-digiid.p12", "inno", "-e", "ECDSA"};

    System.setProperty("digidoc4j.mode", "TEST");
    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void createsContainerWithUnknownSignatureProfile() throws Exception {
    String fileName = "testFiles/tmp/test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "testFiles/p12/signout.p12", "test", "-profile", "Unknown"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.LT, container.getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTMForDDoc() throws Exception {
    String fileName = "testFiles/tmp/test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "testFiles/p12/signout.p12", "test", "-profile", "LT_TM"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.LT_TM, container.getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileTSForDDocReturnsFailureCode() throws Exception {
    exit.expectSystemExitWithStatus(1);

    String fileName = "testFiles/tmp/test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "testFiles/p12/signout.p12", "test", "-profile", "LT"};

    DigiDoc4J.main(params);
  }

  @Test
  public void createsContainerWithSignatureProfileTSAForDDocReturnsFailureCode() throws Exception {
    exit.expectSystemExitWithStatus(1);

    String fileName = "testFiles/tmp/test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "testFiles/p12/signout.p12", "test", "-profile", "LTA"};

    DigiDoc4J.main(params);
  }

  @Test
  @Ignore("JDigiDoc by default returns LT_TM profile but should be B_BES profile")
  public void createsContainerWithSignatureProfileBESForDDoc() throws Exception {
    String fileName = "testFiles/tmp/test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "testFiles/p12/signout.p12", "test", "-profile", "B_BES"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals(SignatureProfile.B_BES, container.getSignatures().get(0).getProfile());
  }

  @Test
  public void createsContainerWithTypeSettingBDoc() throws Exception {
    String fileName = "testFiles/tmp/test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "testFiles/helper-files/test.txt", "text/plain",
        "-pkcs12", "testFiles/p12/signout.p12", "test"};

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
    String fileName = "testFiles/tmp/test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals("DDOC", container.getType());
  }

  @Test
  public void createsContainerWithTypeSettingBasedOnFileExtensionBDoc() throws Exception {
    String fileName = "testFiles/tmp/test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals("BDOC", container.getType());
  }

  @Test
  public void createsContainerWithTypeSettingBDocIfNoSuitableFileExtensionAndNoType() throws Exception {
    System.setProperty("digidoc4j.mode", "TEST");
    String fileName = "testFiles/tmp/test1.test";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = ContainerOpener.open(fileName);
    assertEquals("BDOC", container.getType());
    System.setProperty("digidoc4j.mode", "PROD");
  }

  @Test
  public void createsContainerAndSignsIt() throws Exception {
    exit.expectSystemExitWithStatus(0);
    Files.deleteIfExists(Paths.get("testFiles/tmp/test1.ddoc"));
    String[] params = new String[]{"-in", "testFiles/tmp/test1.ddoc", "-add", "testFiles/helper-files/test.txt", "text/plain", "-pkcs12",
        "testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  @Ignore("Requires a physical smart card")
  public void createContainer_andSignIt_withPkcs11() throws Exception {
    Files.deleteIfExists(Paths.get(testBdocContainer));
    String[] params = new String[]{"-in", testBdocContainer, "-add", "testFiles/helper-files/test.txt", "text/plain", "-pkcs11",
        "/usr/local/lib/opensc-pkcs11.so", "22975", "2"};
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
    String[] params = new String[]{"-in", testBdocContainer, "-add", "testFiles/helper-files/test.txt", "text/plain", "-pkcs11",
        "/usr/local/lib/opensc-pkcs11.so", "01497", "2", "-pkcs12", "testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  public void createsContainerAndAddsFileWithoutMimeType() throws Exception {
    exit.expectSystemExitWithStatus(2);
    Files.deleteIfExists(Paths.get("test1.ddoc"));
    String[] params = new String[]{"-in", "test1.ddoc", "-add", "testFiles/helper-files/test.txt", "-pkcs12",
        "testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  public void createMultipleSignedContainers_whereInputDirIsFile_shouldThrowException() throws Exception {
    String inputFolderPath = testFolder.newFile("inputDir").getPath();
    exit.expectSystemExitWithStatus(6);
    String[] params = new String[]{"-inputDir", inputFolderPath, "-outputDir", outputDirPath, "-pkcs12",
        "testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  public void createMultipleSignedContainers_whereOutputDirIsFile_shouldThrowException() throws Exception {
    String outputDirPath = testFolder.newFile("outputDir").getPath();
    exit.expectSystemExitWithStatus(6);
    String[] params = new String[]{"-inputDir", inputFolderPath, "-outputDir", outputDirPath, "-pkcs12",
        "testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  public void createMultipleSignedContainers_withEmptyInputDir_shouldDoNothing() throws Exception {
    exit.expectSystemExitWithStatus(0);
    String[] params = new String[]{"-inputDir", inputFolderPath, "-outputDir", outputDirPath, "-pkcs12",
        "testFiles/p12/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  public void createMultipleSignedContainers_withinInputDirectory() throws Exception {
    writeStringToFile(new File(inputFolder, "firstDoc.txt"), "Hello daddy");
    writeStringToFile(new File(inputFolder, "secondDoc.pdf"), "John Matrix");
    writeStringToFile(new File(inputFolder, "thirdDoc.acc"), "Major General Franklin Kirby");

    String[] params = new String[]{"-inputDir", inputFolderPath, "-outputDir", outputDirPath, "-pkcs12",
        "testFiles/p12/signout.p12", "test"};

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
        "testFiles/p12/signout.p12", "test", "-type", "DDOC"};

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
        "testFiles/p12/signout.p12", "test"};

    DigiDoc4J.main(params);
  }

  @Test
  public void createSignedContainer_forEachFile_withInputDirectoryAndMimeType() throws Exception {
    writeStringToFile(new File(inputFolder, "firstDoc.txt"), "Hello daddy");
    writeStringToFile(new File(inputFolder, "secondDoc.pdf"), "John Matrix");

    String[] params = new String[]{"-inputDir", inputFolderPath, "-mimeType", "text/xml", "-outputDir", outputDirPath, "-pkcs12",
        "testFiles/p12/signout.p12", "test"};

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
    String filename = "testFiles/tmp/test1.ddoc";
    Container container = ContainerBuilder.
        aContainer(DDOC_CONTAINER_TYPE).
        build();
    container.addDataFile("testFiles/helper-files/test.txt", "text/plain");
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
    String[] params = new String[]{"-in", "testFiles/valid-containers/ddoc_for_testing.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithManifestErrors() throws Exception {
    exit.expectSystemExitWithStatus(1);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Container contains a file named AdditionalFile.txt which is not found in the signature file"));
      }
    });
    String[] params = new String[]{"-in", "testFiles/invalid-containers/manifest_validation_error.asice", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verboseMode() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Opening container testFiles/valid-containers/ddoc_for_testing.ddoc"));
      }
    });
    String[] params = new String[]{"-in", "testFiles/valid-containers/ddoc_for_testing.ddoc", "-verify", "-verbose"};
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
    sout.clear();
    String[] params = new String[]{"-in", "testFiles/invalid-containers/changed_digidoc_test.ddoc", "-verify"};
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
    sout.clear();
    String[] params = new String[]{"-in", "testFiles/invalid-containers/error75.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithoutSignature() throws Exception {
    exit.expectSystemExitWithStatus(1);
    String[] params = new String[]{"-in", "testFiles/invalid-containers/no_signed_doc_no_signature.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithEmptyContainer() throws Exception {
    exit.expectSystemExitWithStatus(1);
    String[] params = new String[]{"-in", "testFiles/invalid-containers/empty_container_no_signature.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void showsUsage() throws Exception {
    exit.expectSystemExitWithStatus(2);
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
    String[] params = new String[]{"-in", "testFiles/invalid-containers/warning.asice", "-verify", "-warnings"};
    copyFile(new File("testFiles/yaml-configurations/digidoc4j_ForBDocWarningTest.yaml"), new File("digidoc4j.yaml"));
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
    String[] params = new String[]{"-in", "testFiles/invalid-containers/empty_container_no_signature.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithWarning() {
    exit.expectSystemExitWithStatus(1);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("	Warning: ERROR: 176 - X509IssuerName has none or invalid " +
            "namespace: null"));
      }
    });
    String[] params = new String[]{"-in", "testFiles/invalid-containers/warning.ddoc", "-verify"};
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
    testExtractingDataFile("testFiles/valid-containers/one_signature.bdoc", "test.txt");
  }

  @Test
  public void extractDataFileFromDdoc() throws Exception {
    testExtractingDataFile("testFiles/valid-containers/ddoc_for_testing.ddoc", "test.txt");
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
    String[] params = new String[]{"-in", "testFiles/valid-containers/one_signature.bdoc", "-extract", "test.txt"};
    DigiDoc4J.main(params);
  }

  @Test
  public void extractDataFile_withNonExistingFile_shouldThrowException() throws Exception {
    final String outputPath = testFolder.newFolder().getPath() + "/output.txt";
    exit.expectSystemExitWithStatus(4);
    String[] params = new String[]{"-in", "testFiles/valid-containers/one_signature.bdoc", "-extract", "notExistingFile.dmc", outputPath};
    DigiDoc4J.main(params);
  }

  private static void forbidSystemExitCall() {
    final SecurityManager preventExitSecurityManager = new SecurityManager() {
      public void checkPermission(Permission permission) {
      }

      @Override
      public void checkExit(int status) {
        super.checkExit(status);
        throw new DigiDoc4JUtilityException(status, "preventing system exist");
      }
    };
    System.setSecurityManager(preventExitSecurityManager);
  }

  void callMainWithoutSystemExit(String[] params) {
    SecurityManager securityManager = System.getSecurityManager();
    forbidSystemExitCall();
    try {
      DigiDoc4J.main(params);
    } catch (DigiDoc4JUtilityException ignore) {
    }
    System.setSecurityManager(securityManager);
  }

  private void assertContainsFile(String outputDirPath, String fileName) {
    File dir = new File(outputDirPath);
    File file = new File(dir, fileName);
    String errorMsg = "'" + fileName + "' is not present in dir " + Arrays.toString(dir.list());
    assertTrue(errorMsg, file.exists());
  }
}
