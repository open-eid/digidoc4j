package org.digidoc4j;

import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import org.digidoc4j.api.Container;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.NotYetImplementedException;
import org.digidoc4j.api.exceptions.SignatureNotFoundException;
import org.digidoc4j.signers.PKCS12Signer;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.digidoc4j.api.Container.DigestAlgorithm.SHA1;
import static org.digidoc4j.api.Container.DigestAlgorithm.SHA256;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

public class ASiCSContainerTest extends DigiDoc4JTestHelper {

  private PKCS12Signer PKCS12_SIGNER;

  @Before
  public void setUp() throws Exception {
    PKCS12_SIGNER = new PKCS12Signer("testFiles/signout.p12", "test");
  }

  @AfterClass
  public static void deleteTemporaryFiles() {
    try {
      DirectoryStream<Path> directoryStream = Files.newDirectoryStream(Paths.get("."));
      for (Path item : directoryStream) {
        String fileName = item.getFileName().toString();
        if (fileName.endsWith("asics") && fileName.startsWith("test")) Files.deleteIfExists(item);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void testSetDigestAlgorithmToSHA256() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.setDigestAlgorithm(SHA256);
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", container.digestAlgorithm.getXmlId());
  }

  @Test
  public void testSetDigestAlgorithmToSHA1() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.setDigestAlgorithm(SHA1);
    assertEquals("http://www.w3.org/2000/09/xmldsig#sha1", container.digestAlgorithm.getXmlId());
  }

  @Test
  public void testSetDigestAlgorithmToNotImplementedDigest() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.setDigestAlgorithm(SHA256);
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", container.digestAlgorithm.getXmlId());
  }

  @Test
  public void testDefaultDigestAlgorithm() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", container.digestAlgorithm.getXmlId());
  }

  @Test
  public void testOpenASiCSDocument() throws Exception {
    ASiCSContainer container = new ASiCSContainer("testFiles/asics_for_testing.asics");
    container.verify();
  }

  @Test
  public void testOpenASiCSDocumentWithTwoSignatures() throws Exception {
    ASiCSContainer container = new ASiCSContainer("testFiles/two_signatures.asics");
    container.verify();
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileWhenFileDoesNotExist() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.addDataFile("notExisting.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileFromInputStreamWithByteArrayConversionFailure() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.addDataFile(new MockInputStream(), "test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddRawSignature() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.addRawSignature(new byte[]{});
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddRawSignatureFromInputStream() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.addRawSignature(new ByteArrayInputStream("test".getBytes()));
  }

  @Test
  public void testSaveASiCSDocumentWithTwoSignatures() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.sign(new PKCS12Signer("testFiles/B4B.pfx", "123456"));
    container.save("testTwoSignatures.asics");

    assertEquals(2, container.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        container.getSignatures().get(0).getSigningCertificate().getSerial());
    assertEquals("5fe0774b8ba12b98d1c2250f076cd7e0ed7259ab",
        container.getSignatures().get(1).getSigningCertificate().getSerial());

    Container openedContainer = Container.open("testTwoSignatures.asics");

    assertEquals(2, openedContainer.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        openedContainer.getSignatures().get(0).getSigningCertificate().getSerial());
    assertEquals("5fe0774b8ba12b98d1c2250f076cd7e0ed7259ab",
        openedContainer.getSignatures().get(1).getSigningCertificate().getSerial());
  }


  @Test
  public void testAddSignaturesToExistingASiCSDocument() throws Exception {
    Container container = Container.open("testFiles/asics_testing_two_signatures.asics");
    container.sign(PKCS12_SIGNER);
    container.save("testAddMultipleSignatures.asics");

    assertEquals(3, container.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        container.getSignatures().get(2).getSigningCertificate().getSerial());

    Container openedContainer = Container.open("testAddMultipleSignatures.asics");

    assertEquals(3, openedContainer.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        openedContainer.getSignatures().get(2).getSigningCertificate().getSerial());

  }

  @Test
  public void testRemoveSignatureWhenOneSignatureExists() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.removeSignature(0);
    container.save("testRemoveSignature.asics");
    assertEquals(0, container.getSignatures().size());

    container = new ASiCSContainer("testRemoveSignature.asics");
    assertEquals(0, container.getSignatures().size());
  }

  @Test
  public void testRemoveSignatureWhenTwoSignaturesExist() throws Exception {
    Container container = Container.open("testFiles/asics_testing_two_signatures.asics");
    container.removeSignature(0);
    container.save("testRemoveSignature.asics");
    assertEquals(1, container.getSignatures().size());

    container = new ASiCSContainer("testRemoveSignature.asics");
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testSaveASiCSDocumentWithOneSignature() throws Exception {
    createSignedASicSDocument("testSaveASiCSDocumentWithOneSignature.asics");
    assertTrue(Files.exists(Paths.get("testSaveASiCSDocumentWithOneSignature.asics")));
  }

  @Test
  public void testVerifySignedDocument() throws Exception {
    ASiCSContainer container = (ASiCSContainer) createSignedASicSDocument("testSaveASiCSDocumentWithOneSignature.asics");
    assertEquals(0, container.verify().size());
  }

  @Test
  public void testTestVerifyOnInvalidDocument() throws Exception {
    ASiCSContainer container = new ASiCSContainer("testFiles/invalid_container.asics");
    assertTrue(container.verify().size() > 0);
  }

  @Test
  public void testRemoveDataFile() throws Exception {
    createSignedASicSDocument("testRemoveDataFile.asics");
    Container container = new ASiCSContainer("testRemoveDataFile.asics");
    assertEquals("test.txt", container.getDataFiles().get(0).getFileName());
    assertEquals(1, container.getDataFiles().size());
    container.removeDataFile("test.txt");
    assertEquals(0, container.getDataFiles().size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemovingNonExistingFile() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.removeDataFile("test1.txt");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddingSameFileSeveralTimes() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddingNotExistingFile() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.addDataFile("notExistingFile.txt", "text/plain");
  }

  @Test
  public void testAddFileAsStream() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    container.addDataFile(stream, "test1.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("testAddFileAsStream.asics");

    Container containerToTest = new ASiCSContainer("testAddFileAsStream.asics");
    assertEquals("test1.txt", containerToTest.getDataFiles().get(0).getFileName());
  }

  @Test
  public void rawSignatureDoesNotThrowExceptionInCloseError() throws IOException {
    ASiCSContainer container = spy(new ASiCSContainer());
    byte[] signature = {0x41};
    MockInputStream value = new MockInputStream();

    doNothing().when(container).addRawSignature(value);
    when(container.getByteArrayInputStream(signature)).thenReturn(value);

    container.addRawSignature(signature);
  }


  @Test(expected = SignatureNotFoundException.class)
  public void testSignatureNotFoundException() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    ASiCSContainer spy = spy(container);

    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setDeterministicId("NotPresentSignature");
    when(spy.getSignatureParameters()).thenReturn(signatureParameters);

    spy.addDataFile("testFiles/test.txt", "text/plain");
    spy.sign(PKCS12_SIGNER);
  }

  @Test
  public void testLargeFileSigning() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    String path = createLargeFile();
    container.addDataFile(path, "text/plain");
    container.sign(PKCS12_SIGNER);
  }

  private String createLargeFile() {
    String fileName = "test_large_file.asics";
    try {
      RandomAccessFile largeFile = new RandomAccessFile(fileName, "rw");
      largeFile.setLength(ASiCSContainer.FILE_SIZE_TO_STREAM + 100);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return fileName;
  }

  @Test
  public void testGetDocumentType() throws Exception {
    createSignedASicSDocument("testGetDocumentType.asics");
    ASiCSContainer container = new ASiCSContainer("testGetDocumentType.asics");
    assertEquals(Container.DocumentType.ASIC_S, container.getDocumentType());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddTwoFilesAsStream() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    container.addDataFile(stream, "test1.txt", "text/plain");
    container.addDataFile(stream, "test2.txt", "text/plain");
  }

  @Test(expected = NotYetImplementedException.class)
  public void testValidate() {
    ASiCSContainer container = new ASiCSContainer();
    container.validate();
  }

  @Test
  public void testLoadConfiguration() throws Exception {
    ASiCSContainer aSiCSContainer = new ASiCSContainer();
    assertEquals(4096, aSiCSContainer.configuration.getMaxDataFileCached());
    aSiCSContainer.loadConfiguration("testFiles/digidoc_test_conf.yaml");
    assertEquals(8192, aSiCSContainer.configuration.getMaxDataFileCached());
  }

  private Container createSignedASicSDocument(String fileName) {
    ASiCSContainer container = new ASiCSContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save(fileName);
    return container;
  }

  private class MockInputStream extends InputStream {

    public MockInputStream() {
    }

    @Override
    public int read() throws IOException {
      return 0;
    }

    @Override
    public int read(@SuppressWarnings("NullableProblems") byte b[], int off, int len) throws IOException {
      throw new IOException();
    }

    @Override
    public void close() throws IOException {
      throw new IOException();
    }
  }
}