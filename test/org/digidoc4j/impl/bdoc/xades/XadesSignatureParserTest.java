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

import java.util.Arrays;
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.bdoc.BDocSignature;
import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;

public class XadesSignatureParserTest {

  static Configuration configuration = new Configuration(Configuration.Mode.TEST);
  private XadesSignatureParser signatureOpener;

  @Before
  public void setUp() throws Exception {
    DSSDocument signedFile = new FileDocument("testFiles/test.txt");
    List<DSSDocument> detachedContents = Arrays.asList(signedFile);
    signatureOpener = new XadesSignatureParser(detachedContents, configuration);
  }

  @Test
  public void openXadesSignature() throws Exception {
    DSSDocument xadesDoc = new FileDocument("testFiles/xades/test-bdoc-ts.xml");
    List<BDocSignature> signatures = signatureOpener.parse(xadesDoc);
    BDocSignature signature = signatures.get(0);
    assertNotNull(signature);
    assertEquals("S0", signature.getId());
    assertEquals(SignatureProfile.LT, signature.getProfile());
    assertNotNull(signature.getSigningCertificate());
  }
}
