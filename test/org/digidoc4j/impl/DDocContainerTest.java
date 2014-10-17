package org.digidoc4j.impl;

import ee.sk.digidoc.DataFile;
import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import org.digidoc4j.Container;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.Signer;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.signers.PKCS12Signer;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import static org.digidoc4j.Container.SignatureProfile.*;
import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

public class DDocContainerTest {
  public static final String TEXT_MIME_TYPE = "text/plain";
  private PKCS12Signer PKCS12_SIGNER;

  @BeforeClass
  public static void setTestMode() {
    System.setProperty("digidoc4j.mode", "TEST");
  }

  @Before
  public void setUp() throws Exception {
    PKCS12_SIGNER = new PKCS12Signer("testFiles/signout.p12", "test".toCharArray());
  }

  @AfterClass
  public static void deleteTemporaryFiles() {
    try {
      DirectoryStream<Path> directoryStream = Files.newDirectoryStream(Paths.get("."));
      for (Path item : directoryStream) {
        String fileName = item.getFileName().toString();
        if (fileName.endsWith("ddoc") && fileName.startsWith("test")) Files.deleteIfExists(item);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Test(expected = DigiDoc4JException.class)
  public void testSaveThrowsException() throws Exception {
    DDocContainer container = new DDocContainer();
    container.save("/not/existing/path/testSaveThrowsException.ddoc");
  }

  @Test
  public void testGetDataFileSize() {
    DDocContainer container = new DDocContainer("testFiles/ddoc_for_testing.ddoc");
    org.digidoc4j.DataFile dataFile = container.getDataFile(0);
    assertEquals(16, dataFile.getFileSize());
  }

  @Test
  public void testSetDigestAlgorithmSHA1() throws Exception {
    DDocContainer container = new DDocContainer();
    container.setDigestAlgorithm(DigestAlgorithm.SHA1);
  }

  @Test(expected = NotSupportedException.class)
  public void testSetDigestAlgorithmOtherThenSHA1() throws Exception {
    DDocContainer container = new DDocContainer();
    container.setDigestAlgorithm(DigestAlgorithm.SHA224);
  }

  @Test
  public void testCanAddTwoDataFilesWithSameName() throws Exception {
    DDocContainer dDocContainer = new DDocContainer();
    dDocContainer.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    dDocContainer.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    dDocContainer.save("test_ddoc_file.ddoc");
    Container container = Container.open("test_ddoc_file.ddoc");
    List<org.digidoc4j.DataFile> dataFiles = container.getDataFiles();
    assertEquals(2, dataFiles.size());
    assertEquals("test.txt", dataFiles.get(0).getName());
    assertEquals("test.txt", dataFiles.get(1).getName());
  }

  @Test
  public void testGetFileId() {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    List<org.digidoc4j.DataFile> dataFiles = container.getDataFiles();

    assertEquals("D0", dataFiles.get(0).getId());
    assertEquals("D1", dataFiles.get(1).getId());
    assertEquals("test.txt", dataFiles.get(0).getName());
    assertEquals("test.txt", dataFiles.get(1).getName());
  }

  @Test
  public void testAddEmptyFile() throws Exception {
    DDocContainer dDocContainer = new DDocContainer();
    //noinspection ResultOfMethodCallIgnored
    new File("test_empty.txt").createNewFile();
    dDocContainer.addDataFile("test_empty.txt", TEXT_MIME_TYPE);
    dDocContainer.save("test_empty.ddoc");
    Container container = Container.open("test_empty.ddoc");
    List<org.digidoc4j.DataFile> dataFiles = container.getDataFiles();
    assertEquals(1, dataFiles.size());
    assertEquals(0, dataFiles.get(0).getFileSize());

    Files.deleteIfExists(Paths.get("test_empty.txt"));
  }

  @Test
  public void getDataFileByIndex() {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.addDataFile("testFiles/test.xml", TEXT_MIME_TYPE);

    assertEquals("D0", container.getDataFile(0).getId());
    assertEquals("D1", container.getDataFile(1).getId());
    assertEquals("test.txt", container.getDataFile(0).getName());
    assertEquals("test.xml", container.getDataFile(1).getName());
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

  @Test
  public void testGetDataFilesWhenNoDataFileExists() {
    DDocContainer container = new DDocContainer();
    assertNull(container.getDataFiles());
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
  public void setsSignatureId() throws Exception {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER, "SIGNATURE-1");
    container.sign(PKCS12_SIGNER, "SIGNATURE-2");
    container.save("setsSignatureId.ddoc");

    container = new DDocContainer("setsSignatureId.ddoc");
    assertEquals("SIGNATURE-1", container.getSignature(0).getId());
    assertEquals("SIGNATURE-2", container.getSignature(1).getId());
  }

  @Test
  public void setsDefaultSignatureId() throws Exception {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.sign(PKCS12_SIGNER);
    container.save("setsDefaultSignatureId.ddoc");

    container = new DDocContainer("setsDefaultSignatureId.ddoc");
    assertEquals("S0", container.getSignature(0).getId());
    assertEquals("S1", container.getSignature(1).getId());
  }

  @Test
  public void setsSignatureIdWithoutOCSP() throws Exception {
    DDocContainer container = new DDocContainer();
    container.setSignatureProfile(BES);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER, "SIGNATURE-1");
    container.sign(PKCS12_SIGNER, "SIGNATURE-2");
    container.save("setsSignatureId.ddoc");

    container = new DDocContainer("setsSignatureId.ddoc");
    assertEquals("SIGNATURE-1", container.getSignature(0).getId());
    assertEquals("SIGNATURE-2", container.getSignature(1).getId());
  }

  @Test
  public void setsDefaultSignatureIdWithoutOCSP() throws Exception {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.setSignatureProfile(BES);
    container.sign(PKCS12_SIGNER);
    container.sign(PKCS12_SIGNER);
    container.save("setsDefaultSignatureId.ddoc");

    container = new DDocContainer("setsDefaultSignatureId.ddoc");
    assertEquals("S0", container.getSignature(0).getId());
    assertEquals("S1", container.getSignature(1).getId());
  }

  @Test
  public void savesToStream() {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.sign(PKCS12_SIGNER);

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
    container.sign(PKCS12_SIGNER);
    container.sign(PKCS12_SIGNER);

    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12", container.getSignature(1).getSigningCertificate().getSerial());
  }

  @Test(expected = DigiDoc4JException.class)
  public void addDataFileAfterSigning() {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.sign(PKCS12_SIGNER);
    container.addDataFile("testFiles/test.xml", TEXT_MIME_TYPE);
  }

  @Test(expected = DigiDoc4JException.class)
  public void removeDataFileAfterSigning() {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.sign(PKCS12_SIGNER);
    container.removeDataFile("testFiles/test.txt");
  }

  @Test
  public void getSignatureWhenNotSigned() {
    DDocContainer container = new DDocContainer();
    assertNull(container.getSignatures());
  }

  @Test(expected = NotSupportedException.class)
  public void timeStampProfileIsNotSupported() throws Exception {
    DDocContainer container = new DDocContainer();
    container.setSignatureProfile(TS);
  }

  @Test(expected = NotSupportedException.class)
  public void timeStampProfileIsNotSupportedForExtension() throws Exception {
    DDocContainer container = new DDocContainer();
    container.setSignatureProfile(BES);
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.sign(PKCS12_SIGNER);
    container.extendTo(TS);
  }

  @Test
  public void extendToTM() throws Exception {
    DDocContainer container = new DDocContainer();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);
    container.setSignatureProfile(BES);
    container.sign(PKCS12_SIGNER);
    container.save("testAddConfirmation.ddoc");
    container = (DDocContainer) Container.open("testAddConfirmation.ddoc");
    assertNull(container.getSignature(0).getOCSPCertificate());

    container.extendTo(TM);
    container.save("testAddedConfirmation.ddoc");
    container = (DDocContainer) Container.open("testAddedConfirmation.ddoc");
    assertNotNull(container.getSignature(0).getOCSPCertificate());
  }

  @Test(expected = DigiDoc4JException.class)
  public void extendToThrowsExceptionForGetConfirmation() throws Exception {
    MockDDocContainer container = new MockDDocContainer();
    container.setSignatureProfile(BES);
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);

    container.sign(PKCS12_SIGNER);

    container.extendTo(TM);
  }

  @Test
  public void getVersion() {
    DDocContainer container = new DDocContainer();
    assertEquals("1.3", container.getVersion());
  }

  @Test(expected = DigiDoc4JException.class)
  public void signThrowsException() throws Exception {
    MockDDocContainer container = new MockDDocContainer();
    container.addDataFile("testFiles/test.txt", TEXT_MIME_TYPE);

    container.sign(PKCS12_SIGNER);

    container.extendTo(TM);
  }

  private class MockDDocContainer extends DDocContainer {
    ee.sk.digidoc.Signature signature = spy(new ee.sk.digidoc.Signature(new SignedDoc()));

    @Override
    public void extendTo(SignatureProfile profile) {
      super.ddoc = spy(new SignedDoc());
      getConfirmationThrowsException();

      ArrayList<ee.sk.digidoc.Signature> signatures = new ArrayList<ee.sk.digidoc.Signature>();
      signatures.add(signature);
      doReturn(signatures).when(ddoc).getSignatures();

      super.extendTo(profile);
    }

    @Override
    ee.sk.digidoc.Signature calculateSignature(Signer signer, String signatureId) {
      return signature;
    }

    @Override
    public Signature sign(Signer signer, String signatureId) {
      getConfirmationThrowsException();
      return super.sign(signer, signatureId);
    }

    private void getConfirmationThrowsException() {
      try {
        doThrow(new DigiDocException(1, "test", new Throwable())).when(signature).getConfirmation();
      } catch (DigiDocException e) {
        e.printStackTrace();
      }
    }
  }
}
