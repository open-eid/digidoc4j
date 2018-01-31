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

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.exceptions.InvalidSignatureException;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.XadesSignatureParser;
import org.digidoc4j.impl.asic.xades.XadesValidationReportGenerator;
import org.digidoc4j.utils.Helper;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class XadesSignatureParserTest extends AbstractTest {

  private final static Logger logger = LoggerFactory.getLogger(XadesSignatureParserTest.class);
  private List<? extends DSSDocument> detachedContents;

  @Test
  public void parseBesSignature() throws Exception {
    XadesValidationReportGenerator xadesReportGenerator = createXadesReportGenerator("src/test/resources/testFiles/xades/test-bes-signature.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    Assert.assertEquals("Assert 1", SignatureProfile.B_BES, signature.getProfile());
    Assert.assertEquals("Assert 2", "id-693869a500c60f0dc262f7287f033d5d", signature.getId());
    Assert.assertEquals("Assert 3", "http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureMethod());
    Assert.assertEquals("Assert 4", new Date(1454928400000L), signature.getSigningTime());
    Assert.assertEquals("Assert 5", "Tallinn", signature.getCity());
    Assert.assertEquals("Assert 6", "Harjumaa", signature.getStateOrProvince());
    Assert.assertEquals("Assert 7", "13456", signature.getPostalCode());
    Assert.assertEquals("Assert 8", "Estonia", signature.getCountryName());
    Assert.assertEquals("Assert 9", "Manager", signature.getSignerRoles().get(0));
    Assert.assertEquals("Assert 10", "Suspicious Fisherman", signature.getSignerRoles().get(1));
    Assert.assertNotNull("Assert 11", signature.getSigningCertificate());
    Assert.assertTrue("Assert 12", StringUtils.startsWith(signature.getSigningCertificate().issuerName(), "C=EE,O=AS Sertifitseerimiskeskus"));
    Assert.assertNull("Assert 13", signature.getOCSPCertificate());
    Assert.assertNull("Assert 14", signature.getOCSPResponseCreationTime());
    Assert.assertNull("Assert 15", signature.getTimeStampTokenCertificate());
    Assert.assertNull("Assert 16", signature.getTimeStampCreationTime());
    Assert.assertNull("Assert 17", signature.getTrustedSigningTime());
  }

  @Test
  public void parseBDocTmSignature() throws Exception {
    XadesValidationReportGenerator xadesReportGenerator = this.createXadesReportGenerator("src/test/resources/testFiles/xades/test-bdoc-tm.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    Assert.assertEquals("Assert 1", SignatureProfile.LT_TM, signature.getProfile());
    Assert.assertEquals("Assert 2", "id-a4fc49d6d0d7f647f6f2f4edde485943", signature.getId());
    Assert.assertNotNull("Assert 3", signature.getOCSPResponseCreationTime());
    Assert.assertEquals("Assert 4", new Date(1454685580000L), signature.getOCSPResponseCreationTime());
    Assert.assertEquals("Assert 5", signature.getOCSPResponseCreationTime(), signature.getTrustedSigningTime());
    Assert.assertNull("Assert 6", signature.getTimeStampTokenCertificate());
    Assert.assertNull("Assert 7", signature.getTimeStampCreationTime());
  }

  @Test
  public void parseBdocTsSignature() throws Exception {
    XadesValidationReportGenerator xadesReportGenerator = this.createXadesReportGenerator("src/test/resources/testFiles/xades/test-bdoc-ts.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    Assert.assertEquals("Assert 1", SignatureProfile.LT, signature.getProfile());
    Assert.assertEquals("Assert 2", "S0", signature.getId());
    Assert.assertEquals("Assert 3", new Date(1454090316000L), signature.getTimeStampCreationTime());
    Assert.assertEquals("Assert 4", signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void parseBDocTsaSignature() throws Exception {
    XadesValidationReportGenerator xadesReportGenerator = this.createXadesReportGenerator("src/test/resources/testFiles/xades/test-bdoc-tsa.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    Assert.assertEquals("Assert 1", SignatureProfile.LTA, signature.getProfile());
    Assert.assertEquals("Assert 2", "id-168ef7d05729874fab1a88705b09b5bb", signature.getId());
    Assert.assertEquals("Assert 3", "http://www.w3.org/2001/04/xmlenc#sha256", signature.getSignatureMethod());
    Assert.assertEquals("Assert 4", new Date(1455032287000L), signature.getSigningTime());
    Assert.assertTrue("Assert 5", StringUtils.startsWith(signature.getSigningCertificate().issuerName(), "C=EE,O=AS Sertifitseerimiskeskus"));
    Assert.assertEquals("Assert 6", new Date(1455032289000L), signature.getOCSPResponseCreationTime());
    Assert.assertEquals("Assert 7", new Date(1455032288000L), signature.getTimeStampCreationTime());
    Assert.assertEquals("Assert 8", signature.getTimeStampCreationTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void serializeSignature() throws Exception {
    XadesValidationReportGenerator xadesReportGenerator = this.createXadesReportGenerator("src/test/resources/testFiles/xades/test-bdoc-tsa.xml");
    XadesSignature signature = new XadesSignatureParser().parse(xadesReportGenerator);
    String serializedPath = this.createTemporaryFile().getPath();
    Helper.serialize(signature, serializedPath);
    signature = Helper.deserializer(serializedPath);
    Assert.assertEquals("Assert 1", "id-168ef7d05729874fab1a88705b09b5bb", signature.getId());
    XAdESSignature dssSignature = signature.getDssSignature();
    Assert.assertNotNull("Assert 2", dssSignature.getReferences());
  }

  @Test(expected = InvalidSignatureException.class)
  public void parsingInvalidSignatureFile_shouldThrowException() throws Exception {
    XadesValidationReportGenerator xadesReportGenerator = this.createXadesReportGenerator("src/test/resources/testFiles/helper-files/test.txt");
    new XadesSignatureParser().parse(xadesReportGenerator);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    this.detachedContents = Arrays.asList(new FileDocument("src/test/resources/testFiles/helper-files/test.txt"));
  }

  private XadesValidationReportGenerator createXadesReportGenerator(String signaturePath) {
    return new XadesValidationReportGenerator(new FileDocument(signaturePath), (List<DSSDocument>) this.detachedContents, this.configuration);
  }

}
