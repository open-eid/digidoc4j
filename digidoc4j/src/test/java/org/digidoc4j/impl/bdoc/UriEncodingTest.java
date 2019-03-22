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

import org.apache.xml.security.signature.Reference;
import org.digidoc4j.*;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.file.Paths;
import java.util.List;

public class UriEncodingTest extends AbstractTest {

  @Test
  // DetachedSignatureBuilder.createReference(...) uses UTF-8 from dss5.0
  public void signatureReferencesUseUriEncodingButManifestUsesPlainUtf8() throws InterruptedException {
    String fileName = "dds_JÜRIÖÖ € žŠ päev.txt";
    String expectedEncoding = "dds_J%C3%9CRI%C3%96%C3%96%20%E2%82%AC%20%C5%BE%C5%A0%20p%C3%A4ev.txt";
    this.signAndAssert(fileName, expectedEncoding);
    // TODO: Also write an assertion to verify that the manifest file does NOT use URI encoding
  }

  @Test
  // DetachedSignatureBuilder.createReference(...) uses UTF-8 from dss5.0
  public void encodeDataFileWithSpecialCharacters() throws Exception {
    String fileName = "et10i_0123456789!#$%&'()+,-. ;=@[]_`}~ et_EE";
    String expectedEncoding = "et10i_0123456789%21%23%24%25%26%27%28%29%2B%2C-.%20%3B%3D%40%5B%5D_%60%7D%7E%20et_EE";
    this.signAndAssert(fileName, expectedEncoding);
  }

  @Test
  @Ignore("https://ec.europa.eu/cefdigital/tracker/browse/DSS-1515")
  public void validatePartialEncoding_shouldBeValid() throws Exception {
    Container container = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/et10_0123456789!#$%&'()+,-. ;=@[]_`}- et_EE_utf8.zip-d_ec.bdoc"), this.configuration);
    Assert.assertTrue(container.validate().isValid());
  }

  @Test
  public void validateContainer_withWhitespaceEncodedAsPlus_shouldBeValid() throws Exception {
    Container container = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/M1n1 Testäöüõ!.txt-TS-d4j.bdoc"), this.configuration);
    Assert.assertTrue(container.validate().isValid());
  }

  /*
   * RESTRICTED METHODS
   */

  private void signAndAssert(String fileName, String expectedEncoding) {
    Signature signature = sign(fileName);
    Assert.assertTrue(signature.validateSignature().isValid());
    List<Reference> referencesInSignature = ((BDocSignature) signature).getOrigin().getReferences();
    Assert.assertEquals(expectedEncoding, referencesInSignature.get(0).getURI());
  }

  private Signature sign(String fileName) {
    return TestDataBuilderUtil.signContainer(ContainerBuilder.aContainer().
        withConfiguration(new Configuration(Configuration.Mode.TEST)).
        withDataFile(new ByteArrayInputStream("file contents".getBytes()), fileName, "application/octet-stream").
        build());
  }

}
