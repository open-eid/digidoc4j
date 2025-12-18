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

import org.digidoc4j.Constant;
import org.digidoc4j.DataFile;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.xmlunit.matchers.CompareMatcher.isIdenticalTo;

public class AsicManifestTest {

  private static final String ROOT_MEDIA_TYPE_PLACEHOLDER = "{ROOT_MEDIA_TYPE}";
  private static final String ENTRY_MEDIA_TYPE_PLACEHOLDER = "{ENTRY_MEDIA_TYPE}";
  private static final String MANIFEST_TEMPLATE = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>" +
          "<manifest:manifest xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\" manifest:version=\"1.2\">" +
          "<manifest:file-entry manifest:full-path=\"/\" manifest:media-type=\"{ROOT_MEDIA_TYPE}\"/>" +
          "<manifest:file-entry manifest:full-path=\"test.txt\" manifest:media-type=\"{ENTRY_MEDIA_TYPE}\"/>" +
          "</manifest:manifest>";

  @Test
  public void getBytes_WhenContainerTypeIsNotSpecified_ReturnsASiCEManifest() throws Exception {
    AsicManifest manifest = new AsicManifest();
    addFileEntry(manifest, "text/plain");

    assertManifestBytes(manifest, MANIFEST_TEMPLATE
            .replace(ROOT_MEDIA_TYPE_PLACEHOLDER, "application/vnd.etsi.asic-e+zip")
            .replace(ENTRY_MEDIA_TYPE_PLACEHOLDER, "text/plain"));
  }

  @Test
  public void getBytes_WhenContainerTypeIsASiCE_ReturnsASiCEManifest() throws Exception {
    AsicManifest manifest = new AsicManifest(Constant.ASICE_CONTAINER_TYPE);
    addFileEntry(manifest, "text/plain");

    assertManifestBytes(manifest, MANIFEST_TEMPLATE
            .replace(ROOT_MEDIA_TYPE_PLACEHOLDER, "application/vnd.etsi.asic-e+zip")
            .replace(ENTRY_MEDIA_TYPE_PLACEHOLDER, "text/plain"));
  }

  @Test
  public void getBytes_WhenContainerTypeIsASiCS_ReturnsASiCSManifest() throws Exception {
    AsicManifest manifest = new AsicManifest(Constant.ASICS_CONTAINER_TYPE);
    addFileEntry(manifest, "text/plain");

    assertManifestBytes(manifest, MANIFEST_TEMPLATE
            .replace(ROOT_MEDIA_TYPE_PLACEHOLDER, "application/vnd.etsi.asic-s+zip")
            .replace(ENTRY_MEDIA_TYPE_PLACEHOLDER, "text/plain"));
  }

  @Test
  public void getBytes_WhenContainerMimeTypeIsGiven_ReturnsManifestContainingEntryWithGivenMimeType() throws Exception {
    AsicManifest manifest = new AsicManifest();
    addFileEntry(manifest, "application/octet-stream");

    assertManifestBytes(manifest, MANIFEST_TEMPLATE
            .replace(ROOT_MEDIA_TYPE_PLACEHOLDER, "application/vnd.etsi.asic-e+zip")
            .replace(ENTRY_MEDIA_TYPE_PLACEHOLDER, "application/octet-stream"));
  }

  private static void addFileEntry(AsicManifest manifest, String fileEntryMimeType) {
    manifest.addFileEntry(new DataFile("src/test/resources/testFiles/helper-files/test.txt", fileEntryMimeType));
  }

  private static void assertManifestBytes(AsicManifest manifest, String expectedXmlString) throws Exception {
    byte[] manifestBytes = manifest.getBytes();

    assertThat(manifestBytes, isIdenticalTo(expectedXmlString));
  }

}
