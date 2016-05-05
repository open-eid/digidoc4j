/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.xades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.InvalidSignatureException;
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
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class XadesSignatureParserTest {

  private final static Logger logger = LoggerFactory.getLogger(XadesSignatureParserTest.class);
  private static Configuration configuration = new Configuration(Configuration.Mode.TEST);

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();
  private List<DSSDocument> detachedContents;

  @Before
  public void setUp() throws Exception {
    DSSDocument signedFile = new FileDocument("testFiles/test.txt");
    detachedContents = Arrays.asList(signedFile);
  }

  @Test
  public void parseBesSignature() throws Exception {
    XadesValidationReportGenerator xadesReportGenerator = createXadesReportGenerator("testFiles/xades/test-bes-signature.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
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
  public void parseBDocTmSignature() throws Exception {
    XadesValidationReportGenerator xadesReportGenerator = createXadesReportGenerator("testFiles/xades/test-bdoc-tm.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    assertEquals(SignatureProfile.LT_TM, signature.getProfile());
    assertEquals("id-a4fc49d6d0d7f647f6f2f4edde485943", signature.getId());
    logger.debug("Getting OCSP certificate");
    logger.debug("Getting OCSP time");
    assertNotNull(signature.getOCSPResponseCreationTime());
    assertEquals(new Date(1454685580000L), signature.getOCSPResponseCreationTime());
    logger.debug("Getting trusted signing time");
    assertEquals(signature.getOCSPResponseCreationTime(), signature.getTrustedSigningTime());
    assertNull(signature.getTimeStampTokenCertificate());
    assertNull(signature.getTimeStampCreationTime());
    logger.debug("Finished testing Timemark signature");
  }

  @Test
  public void parseBdocTsSignature() throws Exception {
    XadesValidationReportGenerator xadesReportGenerator = createXadesReportGenerator("testFiles/xades/test-bdoc-ts.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    assertEquals(SignatureProfile.LT, signature.getProfile());
    assertEquals("S0", signature.getId());
    logger.debug("Getting timestamp time");
    assertEquals(new Date(1454090316000L), signature.getTimeStampCreationTime());
    logger.debug("Checking trusted time");
    assertEquals(signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
    logger.debug("Finished testing Timestamp signature");
  }

  @Test
  public void parseBDocTsaSignature() throws Exception {
    XadesValidationReportGenerator xadesReportGenerator = createXadesReportGenerator("testFiles/xades/test-bdoc-tsa.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    assertEquals(SignatureProfile.LTA, signature.getProfile());
    assertEquals("id-168ef7d05729874fab1a88705b09b5bb", signature.getId());
    assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureMethod());
    assertEquals(new Date(1455032287000L), signature.getSigningTime());
    assertTrue(StringUtils.startsWith(signature.getSigningCertificate().issuerName(), "C=EE,O=AS Sertifitseerimiskeskus"));
    assertEquals(new Date(1455032289000L), signature.getOCSPResponseCreationTime());
    assertEquals(new Date(1455032288000L), signature.getTimeStampCreationTime());
    assertEquals(signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void serializeSignature() throws Exception {
    XadesValidationReportGenerator xadesReportGenerator = createXadesReportGenerator("testFiles/xades/test-bdoc-tsa.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    String serializedPath = testFolder.newFile().getPath();
    Helper.serialize(signature, serializedPath);
    signature = Helper.deserializer(serializedPath);
    assertEquals("id-168ef7d05729874fab1a88705b09b5bb", signature.getId());
    XAdESSignature dssSignature = signature.getDssSignature();
    assertNotNull(dssSignature.getReferences());
  }

  @Test(expected = InvalidSignatureException.class)
  public void parsingInvalidSignatureFile_shouldThrowException() throws Exception {
    XadesValidationReportGenerator xadesReportGenerator = createXadesReportGenerator("testFiles/test.txt");
    new XadesSignatureParser().parse(xadesReportGenerator);
  }

  private XadesValidationReportGenerator createXadesReportGenerator(String signaturePath) {
    DSSDocument signatureDocument = new FileDocument(signaturePath);
    XadesValidationReportGenerator generator = new XadesValidationReportGenerator(signatureDocument, detachedContents, configuration);
    return generator;
  }

}
