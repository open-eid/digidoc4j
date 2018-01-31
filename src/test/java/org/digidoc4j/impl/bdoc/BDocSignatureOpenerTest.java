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

import java.io.File;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignatureOpener;
import org.digidoc4j.utils.Helper;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class BDocSignatureOpenerTest extends AbstractTest {

  private BDocSignatureOpener signatureOpener;

  @Test
  public void openBesSignature() throws Exception {
    List<BDocSignature> signatures = this.signatureOpener.parse(new FileDocument("src/test/resources/testFiles/xades/test-bes-signature.xml"));
    Assert.assertEquals("Assert 1", 1, signatures.size());
    BDocSignature signature = signatures.get(0);
    Assert.assertEquals("Assert 2", "id-693869a500c60f0dc262f7287f033d5d", signature.getId());
    Assert.assertEquals(SignatureProfile.B_BES, signature.getProfile());
    Assert.assertEquals("Assert 3", "id-693869a500c60f0dc262f7287f033d5d", signature.getId());
    Assert.assertEquals("Assert 4", "http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureMethod());
    Assert.assertEquals(new Date(1454928400000L), signature.getSigningTime());
    Assert.assertEquals("Assert 5", "Tallinn", signature.getCity());
    Assert.assertEquals("Assert 6", "Harjumaa", signature.getStateOrProvince());
    Assert.assertEquals("Assert 7", "13456", signature.getPostalCode());
    Assert.assertEquals("Assert 8", "Estonia", signature.getCountryName());
    Assert.assertEquals("Assert 9", "Manager", signature.getSignerRoles().get(0));
    Assert.assertEquals("Assert 10", "Suspicious Fisherman", signature.getSignerRoles().get(1));
    Assert.assertNotNull(signature.getSigningCertificate());
    Assert.assertTrue(StringUtils.startsWith(signature.getSigningCertificate().issuerName(), "C=EE,O=AS Sertifitseerimiskeskus"));
    byte[] signatureInBytes = signature.getAdESSignature();
    SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new InMemoryDocument(signatureInBytes));
    Assert.assertEquals("Assert 11", "id-693869a500c60f0dc262f7287f033d5d", validator.getSignatures().get(0).getId());
    Assert.assertNull("Assert 12", signature.getOCSPCertificate());
    Assert.assertNull("Assert 13", signature.getOCSPResponseCreationTime());
    Assert.assertNull("Assert 14", signature.getTimeStampTokenCertificate());
    Assert.assertNull("Assert 15", signature.getTimeStampCreationTime());
    Assert.assertNull("Assert 16", signature.getTrustedSigningTime());
  }

  @Test
  public void openXadesSignature() throws Exception {
    Date date_2016_29_1_time_19_58_36 = new Date(1454090316000L);
    Date date_2016_29_1_time_19_58_37 = new Date(1454090317000L);
    List<BDocSignature> signatures = this.signatureOpener.parse(new FileDocument("src/test/resources/testFiles/xades/test-bdoc-ts.xml"));
    BDocSignature signature = signatures.get(0);
    Assert.assertNotNull("Assert 1", signature);
    Assert.assertEquals("Assert 2", "S0", signature.getId());
    Assert.assertEquals("Assert 3", SignatureProfile.LT, signature.getProfile());
    Assert.assertEquals("Assert 4", "http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureMethod());
    Assert.assertEquals("Assert 5", date_2016_29_1_time_19_58_36, signature.getSigningTime());
    Assert.assertTrue("Assert 6", StringUtils.startsWith(signature.getSigningCertificate().issuerName(), "C=EE,O=AS Sertifitseerimiskeskus"));
    Assert.assertNotNull("Assert 7", signature.getOCSPCertificate());
    Assert.assertTrue("Assert 8", StringUtils.contains(signature.getOCSPCertificate().getSubjectName(), "OU=OCSP"));
    Assert.assertEquals("Assert 9", date_2016_29_1_time_19_58_37, signature.getOCSPResponseCreationTime());
    Assert.assertEquals("Assert 10", date_2016_29_1_time_19_58_36, signature.getTimeStampCreationTime());
    Assert.assertNotNull("Assert 11", signature.getTimeStampTokenCertificate());
    Assert.assertTrue("Assert 12", StringUtils.contains(signature.getTimeStampTokenCertificate().getSubjectName(), "OU=TSA"));
    Assert.assertEquals("Assert 13", signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void serializeBDocSignature() throws Exception {
    List<BDocSignature> signatures = this.signatureOpener.parse(new FileDocument("src/test/resources/testFiles/xades/test-bdoc-ts.xml"));
    BDocSignature signature = signatures.get(0);
    String serializedPath = this.getFileBy("ser");
    Helper.serialize(signature, serializedPath);
    signature = Helper.deserializer(serializedPath);
    Assert.assertEquals("S0", signature.getId());
  }

  @Test
  public void openXadesSignature_withoutXmlPreamble_shouldBeValid() throws Exception {
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/xades/bdoc-tm-jdigidoc-mobile-id.xml"));
    List<BDocSignature> signatures = this.signatureOpener.parse(new InMemoryDocument(signatureBytes));
    Assert.assertEquals("S935237", signatures.get(0).getId());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    this.signatureOpener = new BDocSignatureOpener(Collections.<DSSDocument>singletonList(
        new FileDocument("src/test/resources/testFiles/helper-files/test.txt")), this.configuration);
  }

}
