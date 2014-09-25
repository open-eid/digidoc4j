package org.digidoc4j.main;

import ee.sk.digidoc.DigiDocException;
import org.digidoc4j.DDocContainer;
import org.digidoc4j.DigiDoc4JTestHelper;
import org.digidoc4j.ValidationResultForDDoc;
import org.digidoc4j.api.Container;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.SignatureNotFoundException;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.Assertion;
import org.junit.contrib.java.lang.system.ExpectedSystemExit;
import org.junit.contrib.java.lang.system.StandardOutputStreamLog;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Permission;

import static java.util.Arrays.asList;
import static org.digidoc4j.api.Configuration.Mode;
import static org.digidoc4j.api.Container.DocumentType.BDOC;
import static org.digidoc4j.api.Container.DocumentType.DDOC;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;


public class DigiDoc4JTest extends DigiDoc4JTestHelper {

  @Rule
  public final ExpectedSystemExit exit = ExpectedSystemExit.none();

  @Rule
  public final StandardOutputStreamLog sout = new StandardOutputStreamLog();

  @After
  public void cleanUp() throws Exception {
    Files.deleteIfExists(Paths.get("test1.ddoc"));
    Files.deleteIfExists(Paths.get("test1.bdoc"));
    Files.deleteIfExists(Paths.get("test1.test"));
  }

  @Test
  public void createsContainerWithTypeSettingDDoc() throws Exception {
    String fileName = "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));


    String[] params = new String[]{"-in", fileName, "-type", "DDOC", "-add", "testFiles/test.txt", "text/plain", "-pkcs12", "testFiles/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(DDOC, container.getDocumentType());
  }

  @Test
  public void createsContainerWithTypeSettingBDoc() throws Exception {
    String fileName = "test1.ddoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "BDOC", "-add", "testFiles/test.txt", "text/plain", "-pkcs12", "testFiles/signout.p12", "test"};

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
    assertEquals(Mode.TEST.toString(), System.getProperty("digidoc4j.mode"));
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

    String[] params = new String[]{"-in", fileName, "-add", "testFiles/test.txt", "text/plain", "-pkcs12", "testFiles/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(DDOC, container.getDocumentType());
  }

  @Test
  public void createsContainerWithTypeSettingBasedOnFileExtensionBDoc() throws Exception {
    String fileName = "test1.bdoc";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "testFiles/test.txt", "text/plain", "-pkcs12", "testFiles/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(BDOC, container.getDocumentType());
  }

  @Test
  public void createsContainerWithTypeSettingBDocIfNoSuitableFileExtensionAndNoType() throws Exception {
    String fileName = "test1.test";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "testFiles/test.txt", "text/plain", "-pkcs12", "testFiles/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    Container container = Container.open(fileName);
    assertEquals(BDOC, container.getDocumentType());
  }

  @Test
  public void createsContainerAndSignsIt() throws Exception {
    exit.expectSystemExitWithStatus(0);
    Files.deleteIfExists(Paths.get("test1.ddoc"));
    String[] params = new String[]{"-in", "test1.ddoc", "-add", "testFiles/test.txt", "text/plain", "-pkcs12", "testFiles/signout.p12", "test"};
    DigiDoc4J.main(params);
  }

  @Test
  public void createsContainerAndAddsFileWithoutMimeType() throws Exception {
    exit.expectSystemExitWithStatus(2);
    Files.deleteIfExists(Paths.get("test1.ddoc"));
    String[] params = new String[]{"-in", "test1.ddoc", "-add", "testFiles/test.txt", "-pkcs12", "testFiles/signout.p12", "test"};
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
        assertEquals("Signature S0 is valid", sout.getLog().trim());
      }
    });
    String[] params = new String[]{"-in", "testFiles/ddoc_for_testing.ddoc", "-verify"};
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
  public void verifyWithFatalError() {
    DDocContainer container = new DDocContainer();
    DDocContainer spy = spy(container);

    DigiDocException exception = new DigiDocException(75, "testException", new Throwable("test Exception"));

    ValidationResultForDDoc validationResultForDDoc = spy(new ValidationResultForDDoc(null, asList(exception)));
    when(validationResultForDDoc.getContainerErrors()).thenReturn(asList(new DigiDoc4JException(exception)));
    when(validationResultForDDoc.hasFatalErrors()).thenReturn(true);

    when(spy.validate()).thenReturn(validationResultForDDoc);

    DigiDoc4J.verify(spy);
    assertEquals("\t75testException; nested exception is: \n\tjava.lang.Throwable: test Exception\n", sout.getLog());
  }

  @Test(expected = SignatureNotFoundException.class)
  public void verifyWithoutFatalError() {
    DDocContainer container = new DDocContainer();
    DDocContainer spy = spy(container);

    DigiDocException exception = new DigiDocException(10, "testException", new Throwable("test Exception"));

    ValidationResultForDDoc validationResultForDDoc = spy(new ValidationResultForDDoc(null, asList(exception)));
    when(validationResultForDDoc.getContainerErrors()).thenReturn(asList(new DigiDoc4JException(exception)));
    when(validationResultForDDoc.hasFatalErrors()).thenReturn(false);

    when(spy.validate()).thenReturn(validationResultForDDoc);

    DigiDoc4J.verify(spy);
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
    } catch (DigiDoc4JUtilityException e) {
    }
    System.setSecurityManager(securityManager);
  }
}