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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.utils.Helper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class BDocSignatureOpenerTest {

  private final static Logger logger = LoggerFactory.getLogger(BDocSignatureOpenerTest.class);
  static Configuration configuration = new Configuration(Configuration.Mode.TEST);
  private BDocSignatureOpener signatureOpener;

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @Before
  public void setUp() throws Exception {
    DSSDocument signedFile = new FileDocument("testFiles/helper-files/test.txt");
    List<DSSDocument> detachedContents = Arrays.asList(signedFile);
    signatureOpener = new BDocSignatureOpener(detachedContents, configuration);
  }

  @Test
  public void openBesSignature() throws Exception {
    DSSDocument xadesDoc = new FileDocument("testFiles/xades/test-bes-signature.xml");
    List<BDocSignature> signatures = signatureOpener.parse(xadesDoc);
    assertEquals(1, signatures.size());
    BDocSignature signature = signatures.get(0);
    assertEquals("id-693869a500c60f0dc262f7287f033d5d", signature.getId());
    assertEquals(SignatureProfile.B_BES, signature.getProfile());
    logger.debug("Getting signature id");
    assertEquals("id-693869a500c60f0dc262f7287f033d5d", signature.getId());
    logger.debug("Getting signature method");
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureMethod());
    logger.debug("Getting signing time");
    assertEquals(new Date(1454928400000L), signature.getSigningTime());
    logger.debug("Getting city");
    assertEquals("Tallinn", signature.getCity());
    logger.debug("Getting state");
    assertEquals("Harjumaa", signature.getStateOrProvince());
    logger.debug("Getting postal code");
    assertEquals("13456", signature.getPostalCode());
    logger.debug("Getting country name");
    assertEquals("Estonia", signature.getCountryName());
    logger.debug("Getting signer roles");
    assertEquals("Manager", signature.getSignerRoles().get(0));
    assertEquals("Suspicious Fisherman", signature.getSignerRoles().get(1));
    logger.debug("Getting signing certificate");
    assertNotNull(signature.getSigningCertificate());
    logger.debug("Getting signing cert subject name");
    assertTrue(StringUtils.startsWith(signature.getSigningCertificate().issuerName(), "C=EE,O=AS Sertifitseerimiskeskus"));
    logger.debug("Getting signature as a byte array");
    byte[] signatureInBytes = signature.getAdESSignature();
    SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new InMemoryDocument(signatureInBytes));
    assertEquals("id-693869a500c60f0dc262f7287f033d5d", validator.getSignatures().get(0).getId());
    logger.debug("Asserting null values");
    assertNull(signature.getOCSPCertificate());
    assertNull(signature.getOCSPResponseCreationTime());
    assertNull(signature.getTimeStampTokenCertificate());
    assertNull(signature.getTimeStampCreationTime());
    assertNull(signature.getTrustedSigningTime());
    logger.debug("Finished testing BES signature");
  }

  @Test
  public void openXadesSignature() throws Exception {
    Date date_2016_29_1_time_19_58_36 = new Date(1454090316000L);
    Date date_2016_29_1_time_19_58_37 = new Date(1454090317000L);
    DSSDocument xadesDoc = new FileDocument("testFiles/xades/test-bdoc-ts.xml");
    List<BDocSignature> signatures = signatureOpener.parse(xadesDoc);
    BDocSignature signature = signatures.get(0);
    assertNotNull(signature);
    assertEquals("S0", signature.getId());
    assertEquals(SignatureProfile.LT, signature.getProfile());
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureMethod());
    assertEquals(date_2016_29_1_time_19_58_36, signature.getSigningTime());
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
  public void serializeBDocSignature() throws Exception {
    DSSDocument xadesDoc = new FileDocument("testFiles/xades/test-bdoc-ts.xml");
    List<BDocSignature> signatures = signatureOpener.parse(xadesDoc);
    BDocSignature signature = signatures.get(0);
    String serializedPath = testFolder.newFile().getPath();
    Helper.serialize(signature, serializedPath);
    signature = Helper.deserializer(serializedPath);
    assertEquals("S0", signature.getId());
  }

  @Test
  public void openXadesSignature_withoutXmlPreamble_shouldBeValid() throws Exception {
    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("testFiles/xades/bdoc-tm-jdigidoc-mobile-id.xml"));
    InMemoryDocument xadesDoc = new InMemoryDocument(signatureBytes);
    List<BDocSignature> signatures = signatureOpener.parse(xadesDoc);
    assertEquals("S935237", signatures.get(0).getId());
  }
}
