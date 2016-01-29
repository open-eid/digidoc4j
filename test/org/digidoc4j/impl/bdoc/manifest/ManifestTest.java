/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.manifest;

import org.digidoc4j.dss.asic.Manifest;
import org.junit.Test;

import java.io.ByteArrayOutputStream;

import static org.custommonkey.xmlunit.XMLAssert.assertXMLEqual;

import eu.europa.esig.dss.FileDocument;

public class ManifestTest {

  @Test
  public void testSave() throws Exception {
    String expectedResult = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
        "<manifest:manifest xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\">" +
        "<manifest:file-entry manifest:media-type=\"application/vnd.etsi.asic-e+zip\" manifest:full-path=\"/\" />" +
        "<manifest:file-entry manifest:media-type=\"text/plain\" manifest:full-path=\"test.txt\" />" +
        "</manifest:manifest>";
    try(ByteArrayOutputStream out = new ByteArrayOutputStream()) {

      Manifest manifest = new Manifest();
      manifest.addFileEntry(new FileDocument("testFiles/test.txt"));
      manifest.save(out);

      assertXMLEqual(expectedResult, new String(out.toByteArray()));
    }
  }
}
