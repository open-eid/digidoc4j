/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.xades;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.AsicSignatureParser;
import org.digidoc4j.utils.Helper;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AsicXadesSignatureOpenerTest extends AbstractTest {

  protected abstract AsicXadesSignatureOpener signatureOpener();
  protected abstract void assertSignatureType(Signature signature);

  @Test
  public void openBesSignature() {
    Signature signature = signatureOpener().open(
            constructXadesSignatureWrapper(new FileDocument("src/test/resources/testFiles/xades/test-bes-signature.xml")));
    assertSignatureType(signature);
    assertEquals(SignatureProfile.B_BES, signature.getProfile());
    assertEquals("id-693869a500c60f0dc262f7287f033d5d", signature.getId());
    assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signature.getSignatureMethod());
    assertEquals(new Date(1454928400000L), signature.getClaimedSigningTime());
    assertEquals("Tallinn", signature.getCity());
    assertEquals("Harjumaa", signature.getStateOrProvince());
    assertEquals("13456", signature.getPostalCode());
    assertEquals("Estonia", signature.getCountryName());
    assertEquals("Manager", signature.getSignerRoles().get(0));
    assertEquals("Suspicious Fisherman", signature.getSignerRoles().get(1));
    assertNotNull(signature.getSigningCertificate());
    assertTrue(StringUtils.startsWith(signature.getSigningCertificate().issuerName(), "C=EE,O=AS Sertifitseerimiskeskus"));
    byte[] signatureInBytes = signature.getAdESSignature();
    SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new InMemoryDocument(signatureInBytes));
    assertEquals("id-693869a500c60f0dc262f7287f033d5d", validator.getSignatures().get(0).getDAIdentifier());
    assertNull(signature.getOCSPCertificate());
    assertNull(signature.getOCSPResponseCreationTime());
    assertNull(signature.getTimeStampTokenCertificate());
    assertNull(signature.getTimeStampCreationTime());
    assertNull(signature.getTrustedSigningTime());
  }

  @Test
  public void openXadesSignature() {
    Date date_2016_29_1_time_19_58_36 = new Date(1454090316000L);
    Date date_2016_29_1_time_19_58_37 = new Date(1454090317000L);
    Signature signature = signatureOpener().open(
            constructXadesSignatureWrapper(new FileDocument("src/test/resources/testFiles/xades/test-bdoc-ts.xml")));
    assertSignatureType(signature);
    assertNotNull(signature);
    assertEquals("S0", signature.getId());
    assertEquals(SignatureProfile.LT, signature.getProfile());
    assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signature.getSignatureMethod());
    assertEquals(date_2016_29_1_time_19_58_36, signature.getTrustedSigningTime());
    assertTrue(StringUtils.startsWith(signature.getSigningCertificate().issuerName(), "C=EE,O=AS Sertifitseerimiskeskus"));
    assertNotNull(signature.getOCSPCertificate());
    assertTrue(StringUtils.contains(signature.getOCSPCertificate().getSubjectName(), "OU=OCSP"));
    assertEquals(date_2016_29_1_time_19_58_37, signature.getOCSPResponseCreationTime());
    assertEquals(date_2016_29_1_time_19_58_36, signature.getTimeStampCreationTime());
    assertNotNull(signature.getTimeStampTokenCertificate());
    assertTrue(StringUtils.contains(signature.getTimeStampTokenCertificate().getSubjectName(), "OU=TSA"));
    assertEquals(signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void serializeBDocSignature() {
    Signature signature = signatureOpener().open(
            constructXadesSignatureWrapper(new FileDocument("src/test/resources/testFiles/xades/test-bdoc-ts.xml")));
    assertSignatureType(signature);
    String serializedPath = getFileBy("ser");
    Helper.serialize(signature, serializedPath);
    signature = Helper.deserializer(serializedPath);
    assertEquals("S0", signature.getId());
  }

  @Test
  public void openXadesSignature_withoutXmlPreamble_shouldBeValid() throws Exception {
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("src/test/resources/testFiles/xades/bdoc-tm-jdigidoc-mobile-id.xml"));
    Signature signature = signatureOpener().open(
            constructXadesSignatureWrapper(new InMemoryDocument(signatureBytes)));
    assertSignatureType(signature);
    assertEquals("S935237", signature.getId());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
  }

  private XadesSignatureWrapper constructXadesSignatureWrapper(DSSDocument document) {
    AsicSignatureParser signatureParser = new AsicSignatureParser(Collections.singletonList(
            new FileDocument("src/test/resources/testFiles/helper-files/test.txt")), configuration);
    XadesSignature signature = signatureParser.parse(document);
    return new XadesSignatureWrapper(signature, document);
  }

}
