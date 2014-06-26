package org.digidoc4j;

import org.junit.Test;

import static org.digidoc4j.ContainerInterface.DigestAlgorithm.SHA1;
import static org.digidoc4j.ContainerInterface.DigestAlgorithm.SHA256;
import static org.junit.Assert.assertEquals;

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
  public void testSetDigestAlgorithmToNotimplementedDigest() throws Exception {
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
    ASiCSContainer container = new ASiCSContainer("asis_testimiseks.asics");
    container.verify();
  }
}