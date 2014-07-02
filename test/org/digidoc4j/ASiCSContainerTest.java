package org.digidoc4j;

import org.digidoc4j.api.exceptions.TwoSignaturesNotAllowedException;
import org.digidoc4j.utils.PKCS12Signer;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.digidoc4j.ContainerInterface.DigestAlgorithm.SHA1;
import static org.digidoc4j.ContainerInterface.DigestAlgorithm.SHA256;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ASiCSContainerTest {

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
    ASiCSContainer container = new ASiCSContainer("asics_testimiseks.asics");
    container.verify();
  }

  @Test
  public void testOpenASiCSDocumentWithTwoSignatures() throws Exception {
    ASiCSContainer container = new ASiCSContainer("asics_testing_two_signatures.asics");
    container.verify();
  }

  @Test(expected = TwoSignaturesNotAllowedException.class)
  public void testSaveASiCSDocumentWithTwoSignatures() throws Exception {
    ASiCSContainer container = new ASiCSContainer();
    container.addDataFile("test.txt", "plain/text");
    container.sign(new PKCS12Signer("signout.p12", "test"));
    container.sign(new PKCS12Signer("B4B.pfx", "123456"));
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
    ASiCSContainer container = new ASiCSContainer("testInvalidContainer.asics");
    assertTrue(container.verify().size() > 0);
  }

  private ContainerInterface createSignedASicSDocument(String fileName) {
    ASiCSContainer container = new ASiCSContainer();
    container.addDataFile("test.txt", "plain/text");
    container.sign(new PKCS12Signer("signout.p12", "test"));
    container.save(fileName);
    return container;
  }

}