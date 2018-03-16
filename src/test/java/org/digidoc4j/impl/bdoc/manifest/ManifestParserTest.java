package org.digidoc4j.impl.bdoc.manifest;

import java.util.Map;

import org.digidoc4j.impl.asic.manifest.ManifestEntry;
import org.digidoc4j.impl.asic.manifest.ManifestParser;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.FileDocument;

public class ManifestParserTest {

  @Test
  public void parseValidManifest() throws Exception {
    FileDocument manifestFile = new FileDocument("src/test/resources/testFiles/manifest/valid-manifest.xml");
    ManifestParser parser = new ManifestParser(manifestFile);
    Map<String, ManifestEntry> items = parser.getManifestFileItems();
    Assert.assertEquals(2, items.size());
    Assert.assertTrue(items.containsKey("sample_file.pdf"));
    ManifestEntry entry = items.get("sample_file.pdf");
    Assert.assertEquals("application/pdf", entry.getMimeType());
  }

  @Test
  public void parseManifestWithInvalidNamespace() throws Exception {
    FileDocument manifestFile = new FileDocument("src/test/resources/testFiles/manifest/manifest-with-different-namespace.xml");
    ManifestParser parser = new ManifestParser(manifestFile);
    Map<String, ManifestEntry> items = parser.getManifestFileItems();
    Assert.assertEquals(1, items.size());
    Assert.assertTrue(items.containsKey("datafile.txt"));
    ManifestEntry entry = items.get("datafile.txt");
    Assert.assertEquals("text/plain", entry.getMimeType());
  }

}
