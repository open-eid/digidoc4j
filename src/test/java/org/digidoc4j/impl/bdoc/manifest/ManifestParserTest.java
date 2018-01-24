package org.digidoc4j.impl.bdoc.manifest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.digidoc4j.impl.asic.manifest.ManifestEntry;
import org.digidoc4j.impl.asic.manifest.ManifestParser;
import org.junit.Test;

import eu.europa.esig.dss.FileDocument;

public class ManifestParserTest {

  @Test
  public void parseValidManifest() throws Exception {
    FileDocument manifestFile = new FileDocument("src/test/resources/testFiles/manifest/valid-manifest.xml");
    ManifestParser parser = new ManifestParser(manifestFile);
    Map<String, ManifestEntry> items = parser.getManifestFileItems();
    assertEquals(2, items.size());
    assertTrue(items.containsKey("sample_file.pdf"));
    ManifestEntry entry = items.get("sample_file.pdf");
    assertEquals("application/pdf", entry.getMimeType());
  }

  @Test
  public void parseManifestWithInvalidNamespace() throws Exception {
    FileDocument manifestFile = new FileDocument("src/test/resources/testFiles/manifest/manifest-with-different-namespace.xml");
    ManifestParser parser = new ManifestParser(manifestFile);
    Map<String, ManifestEntry> items = parser.getManifestFileItems();
    assertEquals(1, items.size());
    assertTrue(items.containsKey("datafile.txt"));
    ManifestEntry entry = items.get("datafile.txt");
    assertEquals("text/plain", entry.getMimeType());

  }
}
