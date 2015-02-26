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
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.junit.After;
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

import static org.apache.commons.io.FileUtils.copyFile;
import static org.digidoc4j.Configuration.Mode;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.digidoc4j.Container.DocumentType.DDOC;
import static org.digidoc4j.Container.SignatureProfile;
import static org.digidoc4j.main.DigiDoc4J.isWarning;
import static org.digidoc4j.utils.Helper.deleteFile;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.*;


public class DigiDoc4JTest extends DigiDoc4JTestHelper {

  @Rule
  public final ExpectedSystemExit exit = ExpectedSystemExit.none();

  @Rule
  public final StandardOutputStreamLog sout = new StandardOutputStreamLog();

  @After
  public void cleanUp() throws Exception {
    deleteFile("digidoc4j.yaml");
    deleteFile("test1.ddoc");
    deleteFile("test1.bdoc");
    deleteFile("test1.test");
  }

  @Test
  public void createsContainerWithTypeSettingDDoc() throws Exception {
    String fileName = "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "testFiles/test.txt", "text/plain",
        "-pkcs12", "testFiles/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(DDOC, container.getDocumentType());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSAForBDoc() throws Exception {
    String fileName = "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "testFiles/test.txt", "text/plain",
        "-pkcs12", "testFiles/signout.p12", "test", "-profile", "LTA"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(SignatureProfile.LTA, container.getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTSForBDoc() throws Exception {
    String fileName = "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "testFiles/test.txt", "text/plain",
        "-pkcs12", "testFiles/signout.p12", "test", "-profile", "LT"};

    System.setProperty("digidoc4j.mode", "TEST");
    callMainWithoutSystemExit(params);


    Container container = Container.open(fileName);
    assertEquals(SignatureProfile.LT, container.getSignature(0).getProfile());
    System.clearProperty("digidoc4j.mode");
  }


  @Test
  public void createsContainerWithSignatureProfileIsBESForBDoc() throws Exception {
    String fileName = "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "testFiles/test.txt", "text/plain",
        "-pkcs12", "testFiles/signout.p12", "test", "-profile", "B_BES"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(SignatureProfile.B_BES, container.getSignature(0).getProfile());
  }

  @Test (expected = IllegalArgumentException.class)
  public void createsECCSignatureWithInvalidEncryptionType() throws Exception {
    String fileName = "createsECCSignatureWithInvalidEncryptionType.bdoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-add", "testFiles/test.txt", "text/plain",
        "-pkcs12", "testFiles/ec-digiid.p12", "inno", "-e", "INVALID"};

    DigiDoc4J.main(params);
  }

  @Test
  public void createsECCSignature() throws Exception {
    String fileName = "createsECCSignature.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "testFiles/test.txt", "text/plain",
        "-pkcs12", "testFiles/ec-digiid.p12", "inno", "-e", "ECDSA"};

    System.setProperty("digidoc4j.mode", "TEST");
    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertTrue(container.validate().isValid());
  }

  @Test
  public void createsContainerWithUnknownSignatureProfile() throws Exception {
    String fileName = "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "testFiles/test.txt", "text/plain",
        "-pkcs12", "testFiles/signout.p12", "test", "-profile", "Unknown"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(SignatureProfile.LT, container.getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileIsTMForDDoc() throws Exception {
    String fileName = "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "testFiles/test.txt", "text/plain",
        "-pkcs12", "testFiles/signout.p12", "test", "-profile", "LT_TM"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(SignatureProfile.LT_TM, container.getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithSignatureProfileTSForDDocReturnsFailureCode() throws Exception {
    exit.expectSystemExitWithStatus(1);

    String fileName = "test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "testFiles/test.txt", "text/plain",
        "-pkcs12", "testFiles/signout.p12", "test", "-profile", "LT"};

    DigiDoc4J.main(params);
  }

  @Test
  public void createsContainerWithSignatureProfileTSAForDDocReturnsFailureCode() throws Exception {
    exit.expectSystemExitWithStatus(1);

    String fileName = "test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "testFiles/test.txt", "text/plain",
        "-pkcs12", "testFiles/signout.p12", "test", "-profile", "LTA"};

    DigiDoc4J.main(params);
  }

  @Test
  @Ignore("JDigiDoc by default returns LT_TM profile but should be B_BES profile")
  public void createsContainerWithSignatureProfileBESForDDoc() throws Exception {
    String fileName = "test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "testFiles/test.txt", "text/plain",
        "-pkcs12", "testFiles/signout.p12", "test", "-profile", "B_BES"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(SignatureProfile.B_BES, container.getSignature(0).getProfile());
  }

  @Test
  public void createsContainerWithTypeSettingBDoc() throws Exception {
    String fileName = "test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "testFiles/test.txt", "text/plain",
        "-pkcs12", "testFiles/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(BDOC, container.getDocumentType());
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
    String fileName = "test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "testFiles/test.txt", "text/plain", "-pkcs12",
        "testFiles/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(DDOC, container.getDocumentType());
  }

  @Test
  public void createsContainerWithTypeSettingBasedOnFileExtensionBDoc() throws Exception {
    String fileName = "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "testFiles/test.txt", "text/plain", "-pkcs12",
        "testFiles/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(BDOC, container.getDocumentType());
  }

  @Test
  public void createsContainerWithTypeSettingBDocIfNoSuitableFileExtensionAndNoType() throws Exception {
    System.setProperty("digidoc4j.mode", "TEST");
    String fileName = "test1.test";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "testFiles/test.txt", "text/plain", "-pkcs12",
        "testFiles/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(BDOC, container.getDocumentType());
    System.setProperty("digidoc4j.mode", "PROD");
  }

  @Test
  public void createsContainerAndSignsIt() throws Exception {
    exit.expectSystemExitWithStatus(0);
    Files.deleteIfExists(Paths.get("test1.ddoc"));
    String[] params = new String[]{"-in", "test1.ddoc", "-add", "testFiles/test.txt", "text/plain", "-pkcs12",
        "testFiles/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  public void createsContainerAndAddsFileWithoutMimeType() throws Exception {
    exit.expectSystemExitWithStatus(2);
    Files.deleteIfExists(Paths.get("test1.ddoc"));
    String[] params = new String[]{"-in", "test1.ddoc", "-add", "testFiles/test.txt", "-pkcs12",
        "testFiles/signout.p12", "test"};
    DigiDoc4J.main(params);
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

    Container container = Container.create(DDOC);
    container.addDataFile("testFiles/test.txt", "text/plain");
    Files.deleteIfExists(Paths.get("test1.ddoc"));
    container.save("test1.ddoc");

    String[] params = new String[]{"-in", "test1.ddoc", "-remove", "test.txt"};
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
    String[] params = new String[]{"-in", "testFiles/ddoc_for_testing.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithManifestErrors() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Container contains a file named AdditionalFile.txt which is not found in the signature file"));
      }
    });
    String[] params = new String[]{"-in", "testFiles/manifest_validation_error.asice", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verboseMode() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Opening container testFiles/ddoc_for_testing.ddoc"));
      }
    });
    String[] params = new String[]{"-in", "testFiles/ddoc_for_testing.ddoc", "-verify", "-verbose"};
    DigiDoc4J.main(params);

  }

  @Test
  public void verifyInValidDDoc() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("Signature S0 is not valid"));
      }
    });
    sout.clear();
    String[] params = new String[]{"-in", "testFiles/changed_digidoc_test.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithFatalError() throws Exception {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("ERROR: 75"));
      }
    });
    sout.clear();
    String[] params = new String[]{"-in", "testFiles/error75.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithoutSignature() throws Exception {
    exit.expectSystemExitWithStatus(1);
    String[] params = new String[]{"-in", "testFiles/no_signed_doc_no_signature.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithEmptyContainer() throws Exception {
    exit.expectSystemExitWithStatus(1);
    String[] params = new String[]{"-in", "testFiles/empty_container_no_signature.ddoc", "-verify"};
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
  @Ignore("RIA VPN")
  public void verifyBDocWithWarning() throws IOException {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(),
            containsString("The signer's certificate is not supported by SSCD!"));
      }
    });
    String[] params = new String[]{"-in", "testFiles/warning.asice", "-verify", "-warnings"};
    copyFile(new File("testFiles/digidoc4j_ForBDocWarningTest.yaml"), new File("digidoc4j.yaml"));
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
    String[] params = new String[]{"-in", "testFiles/empty_container_no_signature.ddoc", "-verify"};
    DigiDoc4J.main(params);
  }

  @Test
  public void verifyDDocWithWarning() {
    exit.expectSystemExitWithStatus(0);
    exit.checkAssertionAfterwards(new Assertion() {
      @Override
      public void checkAssertion() throws Exception {
        assertThat(sout.getLog(), containsString("	Warning: ERROR: 176 - X509IssuerName has none or invalid " +
            "namespace: null"));
      }
    });
    String[] params = new String[]{"-in", "testFiles/warning.ddoc", "-verify"};
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
}
