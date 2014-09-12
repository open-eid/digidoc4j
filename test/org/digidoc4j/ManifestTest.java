package org.digidoc4j;

import org.digidoc4j.api.DataFile;
import org.junit.Test;

import java.io.ByteArrayOutputStream;

import static java.util.Arrays.asList;
import static org.custommonkey.xmlunit.XMLAssert.assertXMLEqual;

public class ManifestTest {

  @Test
  public void testSave() throws Exception {
    String expectedResult = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
        "<manifest:manifest xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\">" +
        "<manifest:file-entry manifest:media-type=\"application/vnd.etsi.asic-e+zip\" manifest:full-path=\"/\" />" +
        "<manifest:file-entry manifest:media-type=\"text/plain\" manifest:full-path=\"test.txt\" />" +
        "</manifest:manifest>";
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    Manifest manifest = new Manifest();
    manifest.addFileEntry(asList(new DataFile("testFiles/test.txt", "text/plain")));
    manifest.save(out);

    assertXMLEqual(expectedResult, new String(out.toByteArray()));
  }
}