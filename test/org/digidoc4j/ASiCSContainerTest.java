package org.digidoc4j;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.digidoc4j.api.Container;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.PKCS12Signer;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;

import static org.digidoc4j.api.Container.DigestAlgorithm.SHA1;
import static org.digidoc4j.api.Container.DigestAlgorithm.SHA256;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

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

  @Test
  public void testSaveASiCSDocumentWithTwoSignatures() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.sign(new PKCS12Signer("testFiles/B4B.pfx", "123456"));
    container.save("asics_testing_two_signatures.asics");
    assertEquals(2, container.getSignatures().size());
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12",
        container.getSignatures().get(0).getSigningCertificate().getSerial());
    assertEquals("5fe0774b8ba12b98d1c2250f076cd7e0ed7259ab",
        container.getSignatures().get(1).getSigningCertificate().getSerial());
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

  private Container createSignedASicSDocument(String fileName) {
    ASiCSContainer container = new ASiCSContainer();
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(PKCS12_SIGNER);
    container.save(fileName);
    return container;
  }

}