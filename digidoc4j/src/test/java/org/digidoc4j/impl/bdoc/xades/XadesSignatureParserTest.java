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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.XadesSignatureParser;
import org.digidoc4j.impl.asic.xades.XadesValidationReportGenerator;
import org.digidoc4j.utils.Helper;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XadesSignatureParserTest extends AbstractTest {

  private List<? extends DSSDocument> detachedContents;

  @Test
  public void parseBesSignature() {
    XadesValidationReportGenerator xadesReportGenerator = createXadesReportGenerator("src/test/resources/testFiles/xades/test-bes-signature.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    assertEquals(SignatureProfile.B_BES, signature.getProfile());
    assertEquals("id-693869a500c60f0dc262f7287f033d5d", signature.getId());
    assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signature.getSignatureMethod());
    assertEquals(new Date(1454928400000L), signature.getSigningTime());
    assertEquals("Tallinn", signature.getCity());
    assertEquals("Harjumaa", signature.getStateOrProvince());
    assertEquals("13456", signature.getPostalCode());
    assertEquals("Estonia", signature.getCountryName());
    assertEquals("Manager", signature.getSignerRoles().get(0));
    assertEquals("Suspicious Fisherman", signature.getSignerRoles().get(1));
    assertNotNull(signature.getSigningCertificate());
    assertTrue(StringUtils.startsWith(signature.getSigningCertificate().issuerName(), "C=EE,O=AS Sertifitseerimiskeskus"));
    assertNull(signature.getOCSPCertificate());
    assertNull(signature.getOCSPResponseCreationTime());
    assertNull(signature.getTimeStampTokenCertificate());
    assertNull(signature.getTimeStampCreationTime());
    assertNull(signature.getTrustedSigningTime());
  }

  @Test
  public void parseBDocTmSignature() {
    XadesValidationReportGenerator xadesReportGenerator = createXadesReportGenerator("src/test/resources/testFiles/xades/test-bdoc-tm.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    assertEquals(SignatureProfile.LT_TM, signature.getProfile());
    assertEquals("id-a4fc49d6d0d7f647f6f2f4edde485943", signature.getId());
    assertNotNull(signature.getOCSPResponseCreationTime());
    assertEquals(new Date(1454685580000L), signature.getOCSPResponseCreationTime());
    assertEquals(signature.getOCSPResponseCreationTime(), signature.getTrustedSigningTime());
    assertNull(signature.getTimeStampTokenCertificate());
    assertNull(signature.getTimeStampCreationTime());
  }

  @Test
  public void parseBdocTsSignature() {
    XadesValidationReportGenerator xadesReportGenerator = createXadesReportGenerator("src/test/resources/testFiles/xades/test-bdoc-ts.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    assertEquals(SignatureProfile.LT, signature.getProfile());
    assertEquals("S0", signature.getId());
    assertEquals(new Date(1454090316000L), signature.getTimeStampCreationTime());
    assertEquals(signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void parseBDocTsaSignature() {
    XadesValidationReportGenerator xadesReportGenerator = createXadesReportGenerator("src/test/resources/testFiles/xades/test-bdoc-tsa.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    assertEquals(SignatureProfile.LTA, signature.getProfile());
    assertEquals("id-168ef7d05729874fab1a88705b09b5bb", signature.getId());
    assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signature.getSignatureMethod());
    assertEquals(new Date(1455032287000L), signature.getSigningTime());
    assertTrue(StringUtils.startsWith(signature.getSigningCertificate().issuerName(), "C=EE,O=AS Sertifitseerimiskeskus"));
    assertEquals(new Date(1455032289000L), signature.getOCSPResponseCreationTime());
    assertEquals(new Date(1455032288000L), signature.getTimeStampCreationTime());
    assertEquals(signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void serializeSignature() throws Exception {
    XadesValidationReportGenerator xadesReportGenerator = createXadesReportGenerator("src/test/resources/testFiles/xades/test-bdoc-tsa.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    String signatureId = signature.getId();
    String serializedPath = createTemporaryFile().getPath();
    Helper.serialize(signature, serializedPath);
    signature = Helper.deserializer(serializedPath);
    assertEquals(signatureId, signature.getId());
    assertEquals("id-168ef7d05729874fab1a88705b09b5bb", signature.getId());
    XAdESSignature dssSignature = signature.getDssSignature();
    assertNotNull(dssSignature.getReferences());
  }

  @Test(expected = InvalidSignatureException.class)
  public void parsingInvalidSignatureFile_shouldThrowException() {
    XadesValidationReportGenerator xadesReportGenerator = this.createXadesReportGenerator("src/test/resources/testFiles/helper-files/test.txt");
    new XadesSignatureParser().parse(xadesReportGenerator);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    configuration = Configuration.of(Configuration.Mode.TEST);
    detachedContents = Arrays.asList(new FileDocument("src/test/resources/testFiles/helper-files/test.txt"));
  }

  private XadesValidationReportGenerator createXadesReportGenerator(String signaturePath) {
    return new XadesValidationReportGenerator(new FileDocument(signaturePath), (List<DSSDocument>) detachedContents, configuration);
  }

}
