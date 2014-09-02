package org.digidoc4j;

import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import org.digidoc4j.api.Container;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.NotYetImplementedException;
import org.digidoc4j.api.exceptions.OCSPRequestFailedException;
import org.digidoc4j.api.exceptions.SignatureNotFoundException;
import org.digidoc4j.signers.PKCS12Signer;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;

import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.digidoc4j.Signatures.XADES_SIGNATURE;
import static org.digidoc4j.api.Container.DigestAlgorithm.SHA1;
import static org.digidoc4j.api.Container.DigestAlgorithm.SHA256;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

public class BDocContainerTest extends DigiDoc4JTestHelper {

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
        if (fileName.endsWith("bdoc") && fileName.startsWith("test")) Files.deleteIfExists(item);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void testSetDigestAlgorithmToSHA256() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setDigestAlgorithm(SHA256);
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", container.digestAlgorithm.getXmlId());
  }

  @Test
  public void testSetDigestAlgorithmToSHA1() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setDigestAlgorithm(SHA1);
    assertEquals("http://www.w3.org/2000/09/xmldsig#sha1", container.digestAlgorithm.getXmlId());
  }

  @Test
  public void testSetDigestAlgorithmToNotImplementedDigest() throws Exception {
    BDocContainer container = new BDocContainer();
    container.setDigestAlgorithm(SHA256);
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", container.digestAlgorithm.getXmlId());
  }

  @Test
  public void testDefaultDigestAlgorithm() throws Exception {
    BDocContainer container = new BDocContainer();
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", container.digestAlgorithm.getXmlId());
  }

  @Test
  public void testOpenBDocDocument() throws Exception {
    BDocContainer container = new BDocContainer("testFiles/asics_for_testing.bdoc");
    container.verify();
  }

  @Test
  public void testOpenBDocDocumentWithTwoSignatures() throws Exception {
    BDocContainer container = new BDocContainer("testFiles/two_signatures.bdoc");
    container.verify();
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileWhenFileDoesNotExist() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("notExisting.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddDataFileFromInputStreamWithByteArrayConversionFailure() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile(new MockInputStream(), "test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddRawSignature() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addRawSignature(new byte[]{});
  }

  @Test(expected = NotYetImplementedException.class)
  public void testAddRawSignatureFromInputStream() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.addRawSignature(new ByteArrayInputStream(XADES_SIGNATURE.getBytes()));
    container.save("test_add_raw_signature.bdoc");

    Container openedContainer = Container.open("test_add_raw_signature.bdoc");
    assertEquals(1, openedContainer.getSignatures().size());
  }

  @Test
  public void testSaveBDocDocumentWithTwoSignatures() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.sign(PKCS12_SIGNER);
    container.save("testTwoSignatures.bdoc");

    assertEquals(2, container.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        container.getSignatures().get(0).getSigningCertificate().getSerial());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        container.getSignatures().get(1).getSigningCertificate().getSerial());

    Container openedContainer = Container.open("testTwoSignatures.bdoc");

    assertEquals(2, openedContainer.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        openedContainer.getSignatures().get(0).getSigningCertificate().getSerial());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        openedContainer.getSignatures().get(1).getSigningCertificate().getSerial());
  }

  @Test(expected = OCSPRequestFailedException.class)
  public void ocspResponseUnknownStatusThrowsException() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(new PKCS12Signer("testFiles/B4B.pfx", "123456"));
  }

  @Test
  public void testAddSignaturesToExistingDocument() throws Exception {
    Container container = Container.open("testFiles/asics_testing_two_signatures.bdoc");
    container.sign(PKCS12_SIGNER);
    container.save("testAddMultipleSignatures.bdoc");

    assertEquals(3, container.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        container.getSignatures().get(2).getSigningCertificate().getSerial());

    Container openedContainer = Container.open("testAddMultipleSignatures.bdoc");

    assertEquals(3, openedContainer.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        openedContainer.getSignatures().get(2).getSigningCertificate().getSerial());

  }


  @Test
  public void testRemoveSignatureWhenOneSignatureExists() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.removeSignature(0);
    container.save("testRemoveSignature.bdoc");
    assertEquals(0, container.getSignatures().size());

    container = new BDocContainer("testRemoveSignature.bdoc");
    assertEquals(0, container.getSignatures().size());
  }

  @Test
  public void testRemoveSignatureWhenTwoSignaturesExist() throws Exception {
    Container container = Container.open("testFiles/asics_testing_two_signatures.bdoc");
    container.removeSignature(0);
    container.save("testRemoveSignature.bdoc");
    assertEquals(1, container.getSignatures().size());

    container = new BDocContainer("testRemoveSignature.bdoc");
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void testSaveDocumentWithOneSignature() throws Exception {
    createSignedBDocDocument("testSaveBDocDocumentWithOneSignature.bdoc");
    assertTrue(Files.exists(Paths.get("testSaveBDocDocumentWithOneSignature.bdoc")));
  }

  @Test
  public void testVerifySignedDocument() throws Exception {
    BDocContainer container = (BDocContainer) createSignedBDocDocument("testSaveBDocDocumentWithOneSignature.bdoc");
    assertEquals(0, container.verify().size());
  }

  @Test
  public void testTestVerifyOnInvalidDocument() throws Exception {
    BDocContainer container = new BDocContainer("testFiles/invalid_container.bdoc");
    assertTrue(container.verify().size() > 0);
  }

  @Test
  public void testRemoveDataFile() throws Exception {
    createSignedBDocDocument("testRemoveDataFile.bdoc");
    Container container = new BDocContainer("testRemoveDataFile.bdoc");
    assertEquals("test.txt", container.getDataFiles().get(0).getFileName());
    assertEquals(1, container.getDataFiles().size());
    container.removeDataFile("test.txt");
    assertEquals(0, container.getDataFiles().size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testRemovingNonExistingFile() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.removeDataFile("test1.txt");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddingSameFileSeveralTimes() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.addDataFile("testFiles/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddingNotExistingFile() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("notExistingFile.txt", "text/plain");
  }

  @Test
  public void testAddFileAsStream() throws Exception {
    BDocContainer container = new BDocContainer();
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    container.addDataFile(stream, "test1.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save("testAddFileAsStream.bdoc");

    Container containerToTest = new BDocContainer("testAddFileAsStream.bdoc");
    assertEquals("test1.txt", containerToTest.getDataFiles().get(0).getFileName());
  }

  @Test
  public void rawSignatureDoesNotThrowExceptionInCloseError() throws IOException {
    BDocContainer container = spy(new BDocContainer());
    byte[] signature = {0x41};
    MockInputStream value = new MockInputStream();

    doNothing().when(container).addRawSignature(value);
    when(container.getByteArrayInputStream(signature)).thenReturn(value);

    container.addRawSignature(signature);
  }


  @Test(expected = SignatureNotFoundException.class)
  public void testSignatureNotFoundException() throws Exception {
    BDocContainer container = new BDocContainer();
    BDocContainer spy = spy(container);

    SignatureParameters signatureParameters = new SignatureParameters();
    signatureParameters.setDeterministicId("NotPresentSignature");
    when(spy.getSignatureParameters()).thenReturn(signatureParameters);

    spy.addDataFile("testFiles/test.txt", "text/plain");
    spy.sign(PKCS12_SIGNER);
  }

  @Test
  public void testLargeFileSigning() throws Exception {
    BDocContainer container = new BDocContainer();
    String path = createLargeFile();
    container.addDataFile(path, "text/plain");
    container.sign(PKCS12_SIGNER);
  }

  private String createLargeFile() {
    String fileName = "test_large_file.bdoc";
    try {
      RandomAccessFile largeFile = new RandomAccessFile(fileName, "rw");
      largeFile.setLength(BDocContainer.FILE_SIZE_TO_STREAM + 100);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return fileName;
  }

  @Test
  public void testGetDocumentType() throws Exception {
    createSignedBDocDocument("testGetDocumentType.bdoc");
    BDocContainer container = new BDocContainer("testGetDocumentType.bdoc");
    assertEquals(Container.DocumentType.BDOC, container.getDocumentType());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAddTwoFilesAsStream() throws Exception {
    BDocContainer container = new BDocContainer();
    ByteArrayInputStream stream = new ByteArrayInputStream("tere, tere".getBytes());
    container.addDataFile(stream, "test1.txt", "text/plain");
    container.addDataFile(stream, "test2.txt", "text/plain");
  }

  @Test(expected = NotYetImplementedException.class)
  public void testValidate() {
    BDocContainer container = new BDocContainer();
    container.validate();
  }

  @Test
  public void testLoadConfiguration() throws Exception {
    BDocContainer container = new BDocContainer();
    assertEquals(4096, container.configuration.getMaxDataFileCachedInMB());
    container.loadConfiguration("testFiles/digidoc_test_conf.yaml");
    assertEquals(8192, container.configuration.getMaxDataFileCachedInMB());
  }

  @Test(expected = NotYetImplementedException.class)
  public void saveToStreamThrowsException() throws Exception {
    BDocContainer container = new BDocContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save(new ByteArrayOutputStream());
  }

  private Container createSignedBDocDocument(String fileName) {
    BDocContainer container = new BDocContainer();
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