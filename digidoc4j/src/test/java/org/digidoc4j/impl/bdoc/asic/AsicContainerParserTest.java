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
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class AsicContainerParserTest extends AbstractTest {

  @Test
  public void findingNextSignatureFileIndex_onEmptyContainer_shouldReturn_null() {
    assertNull(getParseResultFromFile(Paths.get("src/test/resources/testFiles/invalid-containers/asics_without_signatures.bdoc")).getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void findingNextSignatureFileIndex_onContainerWithOneSignature_withoutIndex_shouldReturn_null() {
    assertNull(getParseResultFromFile(Paths.get("src/test/resources/testFiles/invalid-containers/asics_for_testing.bdoc")).getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void findingNextSignatureFileIndex_onContainerWithOneSignature_withIndex0_shouldReturn_0() {
    assertEquals(Integer.valueOf(0), getParseResultFromFile(Paths.get("src/test/resources/testFiles/valid-containers/asics_with_one_signature.bdoc")).getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void findingNextSignatureFileIndex_onContainerWithTwoSignature_shouldReturn_1() {
    assertEquals(Integer.valueOf(1), getParseResultFromFile(Paths.get("src/test/resources/testFiles/valid-containers/asics_testing_two_signatures.bdoc")).getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void parseBdocContainer() {
    assertParseResultValid(getParseResultFromFile(Paths.get("src/test/resources/testFiles/invalid-containers/two_signatures.bdoc")));
  }

  @Test
  public void parseBdocContainerStream() throws Exception {
    assertParseResultValid(new AsicStreamContainerParser(new FileInputStream("src/test/resources/testFiles/invalid-containers/two_signatures.bdoc"), Configuration.getInstance()).read());
  }

  @Test
  public void parseBDoc_containingSignaturesFile_withNonNumericCharacters() {
    AsicParseResult result = getParseResultFromFile(Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-ts-signature-file-name-with-non-numeric-characters.asice"));
    assertIsAsiceContainer(result);
    assertEquals("META-INF/l77Tsignaturesn00B.xml", result.getSignatures().get(0).getSignatureDocument().getName());
    assertNull(result.getCurrentUsedSignatureFileIndex());
  }

  @Test
  public void parseBDocFromFile() {
    AsicParseResult result = getParseResultFromFile
        (Paths.get("src/test/resources/testFiles/valid-containers/23147_weak-warning-sha1.bdoc"));
    for (DataFile dataFile : result.getDataFiles()){
      assertEquals("jdigidoc.cfg", dataFile.getName());
      assertEquals("text/html", dataFile.getMediaType());
    }
  }

  @Test
  public void parseBdocFromStream() throws Exception {
    AsicParseResult result = getParseResultFromStream
        ("src/test/resources/testFiles/valid-containers/23147_weak-warning-sha1.bdoc");
    for (DataFile dataFile : result.getDataFiles()){
      assertEquals("jdigidoc.cfg", dataFile.getName());
      assertEquals("text/html", dataFile.getMediaType());
    }
  }

  /*
   * RESTRICTED METHODS
   */

  private void assertParseResultValid(AsicParseResult result) {
    assertEquals("test.txt", result.getDataFiles().get(0).getName());
    assertEquals("META-INF/signatures0.xml", result.getSignatures().get(0).getSignatureDocument().getName());
    assertEquals("META-INF/signatures1.xml", result.getSignatures().get(1).getSignatureDocument().getName());
    assertEquals(Integer.valueOf(1), result.getCurrentUsedSignatureFileIndex());
    assertIsAsiceContainer(result);
  }

  private void assertIsAsiceContainer(AsicParseResult result) {
    assertTrue(result.getManifestParser().containsManifestFile());
    assertFirstAsicEntryIsMimeType(result);
    assertContainsManifest(result);
  }

  private void assertFirstAsicEntryIsMimeType(AsicParseResult result) {
    List<AsicEntry> asicEntries = result.getAsicEntries();
    assertEquals("mimetype", asicEntries.get(0).getZipEntry().getName());
  }

  private void assertContainsManifest(AsicParseResult result) {
    for (AsicEntry entry : result.getAsicEntries()) {
      if (entry.getZipEntry().getName().equals("META-INF/manifest.xml")) {
        return;
      }
    }
    fail("Parse result does not contain manifest.xml");
  }

}
