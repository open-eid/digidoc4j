/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.manifest;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.digidoc4j.DataFile;
import org.junit.Test;

import java.util.Arrays;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.hasEntry;

public class ManifestParserTest {

  @Test
  public void getManifestFileItems_WhenManifestIsValid_ReturnsMapOfAllItems() {
    FileDocument manifestFile = new FileDocument("src/test/resources/testFiles/manifest/valid-manifest.xml");
    ManifestParser parser = new ManifestParser(manifestFile);

    Map<String, ManifestEntry> result = parser.getManifestFileItems();

    assertThat(result, aMapWithSize(2));
    assertThat(result, hasEntry("DigiDocService_spec_est.pdf",
            new ManifestEntry("DigiDocService_spec_est.pdf", "text/plain")));
    assertThat(result, hasEntry("sample_file.pdf",
            new ManifestEntry("sample_file.pdf", "application/pdf")));
  }

  @Test
  public void getManifestFileItems_WhenManifestNamespaceIsInvalid_ReturnsMapOfAllItems() {
    FileDocument manifestFile = new FileDocument("src/test/resources/testFiles/manifest/manifest-with-different-namespace.xml");
    ManifestParser parser = new ManifestParser(manifestFile);

    Map<String, ManifestEntry> result = parser.getManifestFileItems();

    assertThat(result, aMapWithSize(1));
    assertThat(result, hasEntry("datafile.txt",
            new ManifestEntry("datafile.txt", "text/plain")));
  }

  @Test
  public void getManifestFileItems_WhenMultipleEntriesAreInLexicalOrder_ReturnsMapOfAllItemsRetainingTheirOrder() {
    AsicManifest asicManifest = new AsicManifest();
    asicManifest.addFileEntries(Arrays.asList(
            new DataFile(new byte[0], "a.txt", "text/plain"),
            new DataFile(new byte[0], "b.txt", "text/plain"),
            new DataFile(new byte[0], "c.txt", "text/plain"),
            new DataFile(new byte[0], "d.txt", "text/plain"),
            new DataFile(new byte[0], "e.txt", "text/plain")
    ));
    InMemoryDocument manifestFile = new InMemoryDocument(asicManifest.getBytes());
    ManifestParser parser = new ManifestParser(manifestFile);

    Map<String, ManifestEntry> result = parser.getManifestFileItems();

    assertThat(result, aMapWithSize(5));
    assertThat(result.keySet(), containsInRelativeOrder(
            "a.txt", "b.txt", "c.txt", "d.txt", "e.txt"
    ));
  }

  @Test
  public void getManifestFileItems_WhenMultipleEntriesAreInNonLexicalOrder_ReturnsMapOfAllItemsRetainingTheirOrder() {
    AsicManifest asicManifest = new AsicManifest();
    asicManifest.addFileEntries(Arrays.asList(
            new DataFile(new byte[0], "c.txt", "text/plain"),
            new DataFile(new byte[0], "a.txt", "text/plain"),
            new DataFile(new byte[0], "e.txt", "text/plain"),
            new DataFile(new byte[0], "d.txt", "text/plain"),
            new DataFile(new byte[0], "b.txt", "text/plain")
    ));
    InMemoryDocument manifestFile = new InMemoryDocument(asicManifest.getBytes());
    ManifestParser parser = new ManifestParser(manifestFile);

    Map<String, ManifestEntry> result = parser.getManifestFileItems();

    assertThat(result, aMapWithSize(5));
    assertThat(result.keySet(), containsInRelativeOrder(
            "c.txt", "a.txt", "e.txt", "d.txt", "b.txt"
    ));
  }

}
