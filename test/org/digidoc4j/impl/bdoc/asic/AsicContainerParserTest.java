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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.util.List;

import org.digidoc4j.Configuration;
import org.junit.Assert;
import org.junit.Test;

public class AsicContainerParserTest {

  @Test
  public void findingNextSignatureFileIndex_onEmptyContainer_shouldReturn_null() throws Exception {
    AsicParseResult result = parseContainer("testFiles/asics_without_signatures.bdoc");
    assertEquals(null, result.getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void findingNextSignatureFileIndex_onContainerWithOneSignature_withoutIndex_shouldReturn_null() throws Exception {
    AsicParseResult result = parseContainer("testFiles/asics_for_testing.bdoc");
    assertEquals(null, result.getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void findingNextSignatureFileIndex_onContainerWithOneSignature_withIndex0_shouldReturn_0() throws Exception {
    AsicParseResult result = parseContainer("testFiles/asics_with_one_signature.bdoc");
    assertEquals(Integer.valueOf(0), result.getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void findingNextSignatureFileIndex_onContainerWithTwoSignature_shouldReturn_1() throws Exception {
    AsicParseResult result = parseContainer("testFiles/asics_testing_two_signatures.bdoc");
    assertEquals(Integer.valueOf(1), result.getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void parseBdocContainer() throws Exception {
    AsicParseResult result = parseContainer("testFiles/two_signatures.bdoc");
    assertParseResultValid(result);
  }

  @Test
  public void parseBdocContainerStream() throws Exception {
    AsicContainerParser parser = new AsicStreamContainerParser(new FileInputStream("testFiles/two_signatures.bdoc"), Configuration.getInstance());
    AsicParseResult result = parser.read();
    assertParseResultValid(result);
  }

  private AsicParseResult parseContainer(String path) {
    AsicContainerParser parser = new AsicFileContainerParser(path, Configuration.getInstance());
    AsicParseResult result = parser.read();
    return result;
  }

  private void assertParseResultValid(AsicParseResult result) {
    assertEquals("test.txt", result.getDataFiles().get(0).getName());
    assertEquals("META-INF/signatures0.xml", result.getSignatures().get(0).getName());
    assertEquals("META-INF/signatures1.xml", result.getSignatures().get(1).getName());
    assertEquals(Integer.valueOf(1), result.getCurrentUsedSignatureFileIndex());
    assertTrue(result.getManifestParser().containsManifestFile());
    assertFirstAsicEntryIsMimeType(result);
    assertContainsManifest(result);
  }

  private void assertFirstAsicEntryIsMimeType(AsicParseResult result) {
    List<AsicEntry> asicEntries = result.getAsicEntries();
    assertEquals("mimetype", asicEntries.get(0).getZipEntry().getName());
  }

  private void assertContainsManifest(AsicParseResult result) {
    for(AsicEntry entry: result.getAsicEntries()) {
      if(entry.getZipEntry().getName().equals("META-INF/manifest.xml")) {
        return;
      }
    }
    assertTrue("Parse result does not contain manifest.xml", false);
  }
}
