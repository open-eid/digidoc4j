/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import static java.lang.Thread.sleep;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Assert;
import org.junit.Test;

public class ExtendingBDocContainerTest extends AbstractTest {

  private String containerLocation;

  @Test
  public void extendFromB_BESToTS() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    container.saveAsFile(this.containerLocation);
    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());
    container = TestDataBuilderUtil.open(this.containerLocation);
    container.extendSignatureProfile(SignatureProfile.LT);
    container.saveAsFile(this.getFileBy("bdoc"));
    Assert.assertEquals(1, container.getSignatures().size());
    Signature signature = container.getSignatures().get(0);
    Assert.assertNotNull(signature.getOCSPCertificate());
    Assert.assertEquals(SignatureProfile.LT, signature.getProfile());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void extendFromEpesToLT_TM() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.B_EPES, this.pkcs12SignatureToken);
    container.saveAsFile(this.containerLocation);
    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());
    container = TestDataBuilderUtil.open(this.containerLocation);
    container.extendSignatureProfile(SignatureProfile.LT_TM);
    container.saveAsFile(this.getFileBy("bdoc"));
    Assert.assertEquals(1, container.getSignatures().size());
    Signature signature = container.getSignatures().get(0);
    Assert.assertNotNull(signature.getOCSPCertificate());
    Assert.assertEquals(SignatureProfile.LT_TM, signature.getProfile());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void extendFromB_BESToLTA() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    container.saveAsFile(this.containerLocation);
    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());
    container = TestDataBuilderUtil.open(this.containerLocation);
    container.extendSignatureProfile(SignatureProfile.LTA);
    container.saveAsFile(this.getFileBy("bdoc"));
    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
  }

  @Test(expected = NotSupportedException.class)
  public void extendFromB_BESToLT_TMThrowsException() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    container.extendSignatureProfile(SignatureProfile.LT_TM);
  }

  @Test(expected = NotSupportedException.class)
  public void extendFromEpesToLTThrowsException() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.B_EPES, this.pkcs12SignatureToken);
    container.extendSignatureProfile(SignatureProfile.LT);
  }

  @Test(expected = NotSupportedException.class)
  public void extendFromEpesToLTAThrowsException() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.B_EPES, this.pkcs12SignatureToken);
    container.extendSignatureProfile(SignatureProfile.LTA);
  }

  @Test(expected = NotSupportedException.class)
  public void extendFromLTToLT_TMThrowsException() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.LT, this.pkcs12SignatureToken);
    container.extendSignatureProfile(SignatureProfile.LT_TM);
  }

  @Test(expected = NotSupportedException.class)
  public void extendFromLTAToLT_TMThrowsException() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.LTA, this.pkcs12SignatureToken);
    container.extendSignatureProfile(SignatureProfile.LT_TM);
  }

  @Test(expected = NotSupportedException.class)
  public void extendFromLTToBESThrowsException() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.LT, this.pkcs12SignatureToken);
    container.extendSignatureProfile(SignatureProfile.B_BES);
  }

  @Test(expected = NotSupportedException.class)
  public void extendFromLTToEPESThrowsException() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.LT, this.pkcs12SignatureToken);
    container.extendSignatureProfile(SignatureProfile.B_EPES);
  }

  @Test(expected = NotSupportedException.class)
  public void extendFromLT_TMToLTThrowsException() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.LT_TM, this.pkcs12SignatureToken);
    container.extendSignatureProfile(SignatureProfile.LT);
  }

  @Test(expected = DigiDoc4JException.class)
  public void extendToWhenConfirmationAlreadyExists() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    container.saveAsFile(this.containerLocation);
    Assert.assertEquals(1, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());
    container = TestDataBuilderUtil.open(this.containerLocation);
    container.extendSignatureProfile(SignatureProfile.LT);
    container.extendSignatureProfile(SignatureProfile.LT);
  }

  @Test
  public void extendToWithMultipleSignatures() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    this.createSignatureBy(container, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    container.saveAsFile(this.containerLocation);
    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());
    Assert.assertNull(container.getSignatures().get(1).getOCSPCertificate());
    container = TestDataBuilderUtil.open(this.containerLocation);
    container.extendSignatureProfile(SignatureProfile.LT);
    String containerPath = this.getFileBy("bdoc");
    container.saveAsFile(containerPath);
    container = TestDataBuilderUtil.open(containerPath);
    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    Assert.assertNotNull(container.getSignatures().get(1).getOCSPCertificate());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void extendToWithMultipleSignaturesAndMultipleFiles() throws Exception {
    Container container = this.createNonEmptyContainer();
    container.addDataFile("src/test/resources/testFiles/helper-files/test.xml", "text/xml");
    this.createSignatureBy(container, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    this.createSignatureBy(container, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    container.saveAsFile(this.containerLocation);
    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertEquals(2, container.getDataFiles().size());
    Assert.assertNull(container.getSignatures().get(0).getOCSPCertificate());
    Assert.assertNull(container.getSignatures().get(1).getOCSPCertificate());
    container = TestDataBuilderUtil.open(this.containerLocation);
    container.extendSignatureProfile(SignatureProfile.LT);
    container.saveAsFile(this.getFileBy("bdoc"));
    Assert.assertEquals(2, container.getSignatures().size());
    Assert.assertEquals(2, container.getDataFiles().size());
    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    Assert.assertNotNull(container.getSignatures().get(1).getOCSPCertificate());
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void testContainerExtensionFromLTtoLTA() throws Exception {
    Container container = this.createNonEmptyContainer();
    this.createSignatureBy(container, SignatureProfile.LT, this.pkcs12SignatureToken);
    sleep(1100);
    container.extendSignatureProfile(SignatureProfile.LTA);
    Assert.assertNotNull(container.getSignatures().get(0).getOCSPCertificate());
    TestAssert.assertContainerIsValid(container);
  }

  @Test(expected = NotSupportedException.class)
  public void extensionNotPossibleWhenSignatureLevelIsSame() throws Exception {
    Container container = this.createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    this.createSignatureBy(container, SignatureProfile.LTA, this.pkcs12SignatureToken);
    container.extendSignatureProfile(SignatureProfile.LTA);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.containerLocation = this.getFileBy("bdoc");
  }

}