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

import java.util.Arrays;

import org.custommonkey.xmlunit.XMLAssert;
import org.digidoc4j.DataFile;
import org.digidoc4j.impl.asic.manifest.AsicManifest;
import org.junit.Test;

public class ManifestTest {

  @Test
  public void testSave() throws Exception {
    String expectedResult = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
        "<manifest:manifest xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\">" +
        "<manifest:file-entry manifest:media-type=\"application/vnd.etsi.asic-e+zip\" manifest:full-path=\"/\" />" +
        "<manifest:file-entry manifest:media-type=\"text/plain\" manifest:full-path=\"test.txt\" />" +
        "</manifest:manifest>";
    AsicManifest manifest = new AsicManifest();
    manifest.addFileEntry(Arrays.asList(new DataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain")));
    byte[] manifestBytes = manifest.getBytes();
    XMLAssert.assertXMLEqual(expectedResult, new String(manifestBytes));
  }

}
