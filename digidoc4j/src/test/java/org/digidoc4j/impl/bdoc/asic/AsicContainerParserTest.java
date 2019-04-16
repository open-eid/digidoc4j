/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.asic;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.impl.asic.AsicEntry;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicStreamContainerParser;
import org.junit.Assert;
import org.junit.Test;

import java.io.FileInputStream;
import java.nio.file.Paths;
import java.util.List;

public class AsicContainerParserTest extends AbstractTest {

  @Test
  public void findingNextSignatureFileIndex_onEmptyContainer_shouldReturn_null() throws Exception {
    Assert.assertEquals(null, this.getParseResultFromFile(Paths.get("src/test/resources/testFiles/invalid-containers/asics_without_signatures.bdoc")).getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void findingNextSignatureFileIndex_onContainerWithOneSignature_withoutIndex_shouldReturn_null() throws Exception {
    Assert.assertEquals(null, this.getParseResultFromFile(Paths.get("src/test/resources/testFiles/invalid-containers/asics_for_testing.bdoc")).getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void findingNextSignatureFileIndex_onContainerWithOneSignature_withIndex0_shouldReturn_0() throws Exception {
    Assert.assertEquals(Integer.valueOf(0), this.getParseResultFromFile(Paths.get("src/test/resources/testFiles/valid-containers/asics_with_one_signature.bdoc")).getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void findingNextSignatureFileIndex_onContainerWithTwoSignature_shouldReturn_1() throws Exception {
    Assert.assertEquals(Integer.valueOf(1), this.getParseResultFromFile(Paths.get("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc")).getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void parseBdocContainer() throws Exception {
    this.assertParseResultValid(this.getParseResultFromFile(Paths.get("src/test/resources/testFiles/invalid-containers/two_signatures.bdoc")));
  }

  @Test
  public void parseBdocContainerStream() throws Exception {
    this.assertParseResultValid(new AsicStreamContainerParser(new FileInputStream("src/test/resources/testFiles/invalid-containers/two_signatures.bdoc"), Configuration.getInstance()).read());
  }

  @Test
  public void parseBDoc_containingSignaturesFile_withNonNumericCharacters() throws Exception {
    AsicParseResult result = this.getParseResultFromFile(Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-ts-signature-file-name-with-non-numeric-characters.asice"));
    this.assertIsAsiceContainer(result);
    Assert.assertEquals("META-INF/l77Tsignaturesn00B.xml", result.getSignatures().get(0).getSignatureDocument().getName());
    Assert.assertNull(result.getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void parseBDocFromFile() throws Exception {
    AsicParseResult result = this.getParseResultFromFile
        (Paths.get("src/test/resources/testFiles/valid-containers/23147_weak-warning-sha1.bdoc"));
    for (DataFile dataFile : result.getDataFiles()){
      Assert.assertEquals(dataFile.getName(), "jdigidoc.cfg");
      Assert.assertEquals(dataFile.getMediaType(), "text/html");
    }
  }

  @Test
  public void parseBdocFromStream() throws Exception {
    AsicParseResult result = getParseResultFromStream
        ("src/test/resources/testFiles/valid-containers/23147_weak-warning-sha1.bdoc");
    for (DataFile dataFile : result.getDataFiles()){
      Assert.assertEquals(dataFile.getName(), "jdigidoc.cfg");
      Assert.assertEquals(dataFile.getMediaType(), "text/html");
    }
  }

  /*
   * RESTRICTED METHODS
   */

  private void assertParseResultValid(AsicParseResult result) {
    Assert.assertEquals("test.txt", result.getDataFiles().get(0).getName());
    Assert.assertEquals("META-INF/signatures0.xml", result.getSignatures().get(0).getSignatureDocument().getName());
    Assert.assertEquals("META-INF/signatures1.xml", result.getSignatures().get(1).getSignatureDocument().getName());
    Assert.assertEquals(Integer.valueOf(1), result.getCurrentUsedSignatureFileIndex());
    this.assertIsAsiceContainer(result);
  }

  private void assertIsAsiceContainer(AsicParseResult result) {
    Assert.assertTrue(result.getManifestParser().containsManifestFile());
    this.assertFirstAsicEntryIsMimeType(result);
    this.assertContainsManifest(result);
  }

  private void assertFirstAsicEntryIsMimeType(AsicParseResult result) {
    List<AsicEntry> asicEntries = result.getAsicEntries();
    Assert.assertEquals("mimetype", asicEntries.get(0).getZipEntry().getName());
  }

  private void assertContainsManifest(AsicParseResult result) {
    for (AsicEntry entry : result.getAsicEntries()) {
      if (entry.getZipEntry().getName().equals("META-INF/manifest.xml")) {
        return;
      }
    }
    Assert.assertTrue("Parse result does not contain manifest.xml", false);
  }

}
