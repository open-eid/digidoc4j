package org.digidoc4j;

import ee.sk.digidoc.DataFile;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import org.digidoc4j.api.Container;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.PKCS12Signer;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

public class DDocContainerTest {
  public static final String TEXT_MIME_TYPE = "text/plain";
  private PKCS12Signer pkcs12Signer;

  @BeforeClass
  public static void setTestMode() {
    System.setProperty("digidoc4j.mode", "TEST");
  }

  @Before
  public void setUp() throws Exception {
    pkcs12Signer = new PKCS12Signer("testFiles/signout.p12", "test".toCharArray());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testSaveThrowsException() throws Exception {
    DDocContainer container = new DDocContainer();
    container.save("/not/existing/path/testSaveThrowsException.ddoc");
  }

  @Test
  public void testSetDigestAlgorithm() throws Exception {
    DDocContainer container = new DDocContainer();
    container.setDigestAlgorithm(Container.DigestAlgorithm.SHA1);
  }

  @Test
  public void testFatalError() throws Exception {
    DDocContainer container = new DDocContainer();
    container.setDigestAlgorithm(Container.DigestAlgorithm.SHA1);
  }

  @Test
  public void testCanAddTwoDataFilesWithSameName() throws Exception {
    DDocContainer dDocContainer = new DDocContainer();
    dDocContainer.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    dDocContainer.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    dDocContainer.save("test_ddoc_file.ddoc");
    Container container = Container.open("test_ddoc_file.ddoc");
    List<org.digidoc4j.api.DataFile> dataFiles = container.getDataFiles();
    assertEquals(2, dataFiles.size());
    assertEquals("test.txt", dataFiles.get(0).getFileName());
    assertEquals("test.txt", dataFiles.get(1).getFileName());
    Files.deleteIfExists(Paths.get("test_ddoc_file.ddoc"));
  }

  @Test
  public void getDataFileByIndex() {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.addDataFile("testFiles/test.xml", TEXT_MIME_TYPE);

    assertEquals("test.xml", container.getDataFile(1).getFileName());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddFileFromStreamToDDocThrowsException() throws DigiDocException {
    SignedDoc ddoc = mock(SignedDoc.class);
    when(ddoc.getNewDataFileId()).thenReturn("A");
    when(ddoc.getFormat()).thenReturn("SignedDoc.FORMAT_DDOC");
    doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(ddoc).addDataFile(any(ee.sk.digidoc.DataFile.class));

    DDocContainer container = new DDocContainer(ddoc);
    container.addDataFile(new ByteArrayInputStream(new byte[]{0x42}), "testFromStream.txt", TEXT_MIME_TYPE);
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileThrowsException() throws Exception {
    SignedDoc ddoc = mock(SignedDoc.class);
    doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(ddoc).addDataFile(any(File.class), any(String.class), any(String.class));

    DDocContainer container = new DDocContainer(ddoc);
    container.addDataFile("testFiles/test.txt", "");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testGetDataFileThrowsException() throws Exception {
    SignedDoc ddoc = spy(new SignedDoc("DIGIDOC-XML", "1.3"));

    ee.sk.digidoc.DataFile dataFile = mock(ee.sk.digidoc.DataFile.class);
    doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(dataFile).getBody();
    ArrayList<ee.sk.digidoc.DataFile> mockedDataFiles = new ArrayList<ee.sk.digidoc.DataFile>();
    mockedDataFiles.add(dataFile);
    doReturn(mockedDataFiles).when(ddoc).getDataFiles();

    DDocContainer container = new DDocContainer(ddoc);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.getDataFiles();
  }

  @Test(expected = DigiDoc4JException.class)
  public void removeDataFileWhenNotFound() throws Exception {
    DDocContainer dDocContainer = new DDocContainer();
    dDocContainer.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    dDocContainer.removeDataFile("NotThere.txt");
  }

  @Test(expected = DigiDoc4JException.class)
  public void removeDataFileThrowsException() throws Exception {
    SignedDoc ddoc = mock(SignedDoc.class);

    ArrayList<ee.sk.digidoc.DataFile> mockedDataFiles = new ArrayList<ee.sk.digidoc.DataFile>();
    DataFile dataFile = mock(DataFile.class);
    when(dataFile.getFileName()).thenReturn("test.txt");
    mockedDataFiles.add(dataFile);
    doReturn(mockedDataFiles).when(ddoc).getDataFiles();

    doThrow(new DigiDocException(100, "testException", new Throwable("test Exception"))).
        when(ddoc).removeDataFile(anyInt());

    DDocContainer container = new DDocContainer(ddoc);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.removeDataFile("test.txt");
  }

  @Test(expected = DigiDoc4JException.class)
  public void containerWithFileNameThrowsException() throws Exception {
    new DDocContainer("file_not_exists");
  }

  @Test
  public void savesToStream() {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.sign(pkcs12Signer);

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    container.save(out);
    assertTrue(out.size() != 0);
  }

  @Test(expected = DigiDoc4JException.class)
  public void savesToStreamThrowsException() throws Exception {
    SignedDoc ddoc = mock(SignedDoc.class);
    DigiDocException testException = new DigiDocException(100, "testException", new Throwable("test Exception"));
    doThrow(testException).when(ddoc).writeToStream(any(OutputStream.class));

    DDocContainer container = new DDocContainer(ddoc);
    container.save(new ByteArrayOutputStream());
  }

  @Test(expected = DigiDoc4JException.class)
  public void openFromStreamThrowsException() throws IOException {
    FileInputStream stream = new FileInputStream(new File("testFiles/test.txt"));
    stream.close();
    new DDocContainer(stream);
  }

  @Test
  public void getSignatureByIndex() throws CertificateEncodingException {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.sign(pkcs12Signer);
    container.sign(pkcs12Signer);

    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12", container.getSignature(1).getSigningCertificate().getSerial());
  }

  @Test(expected = DigiDoc4JException.class)
  public void addDataFileAfterSigning() {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.sign(pkcs12Signer);
    container.addDataFile("testFiles/test.xml", TEXT_MIME_TYPE);
  }

  @Test(expected = DigiDoc4JException.class)
  public void removeDataFileAfterSigning() {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.sign(pkcs12Signer);
    container.removeDataFile("testFiles/test.txt");
  }

  @Test
  public void getSignatureWhenNotSigned() {
    DDocContainer container = new DDocContainer();
    assertNull(container.getSignatures());
  }

  @Test
  public void getSignatureWhenNoDocument() {
    MockDDocContainer container = new MockDDocContainer();
    assertNull(container.getSignatures());
  }

  @Test
  public void addConfirmation() throws Exception {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.signWithoutOCSP(pkcs12Signer);
    assertNull(container.getSignature(0).getOCSPCertificate());
  }

  private class MockDDocContainer extends DDocContainer {
    private SignedDoc ddoc;

    public MockDDocContainer() {
      super();
      ddoc = null;
    }
  }
}
