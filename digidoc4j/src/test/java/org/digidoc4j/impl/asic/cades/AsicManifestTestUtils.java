/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.cades;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.apache.commons.lang3.ArrayUtils;

import java.nio.charset.StandardCharsets;

public final class AsicManifestTestUtils {

  public static final String MANIFEST_NAME = "ManifestName.xml";
  public static final String XML_DOCUMENT_HEADER = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>";
  public static final String ASIC_MANIFEST_ELEMENT_START = "<asic:ASiCManifest xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\">";
  public static final String ASIC_MANIFEST_ELEMENT_END = "</asic:ASiCManifest>";

  public static String createAsicManifestXmlString(String... content) {
    StringBuilder sb = new StringBuilder(XML_DOCUMENT_HEADER);
    sb.append(ASIC_MANIFEST_ELEMENT_START);
    for (String string : content) {
      sb.append(string);
    }
    sb.append(ASIC_MANIFEST_ELEMENT_END);
    return sb.toString();
  }

  public static DSSDocument createAsicManifestXmlDocument(String... content) {
    return new InMemoryDocument(
            createAsicManifestXmlString(content).getBytes(StandardCharsets.UTF_8),
            MANIFEST_NAME,
            MimeTypeEnum.XML
    );
  }

  public static String createAsicSigReferenceXmlElement(String mimeType, String uri) {
    StringBuilder sb = new StringBuilder("<asic:SigReference");
    if (mimeType != null) {
      sb.append(" MimeType=\"").append(mimeType).append('"');
    }
    if (uri != null) {
      sb.append(" URI=\"").append(uri).append('"');
    }
    return sb.append("/>").toString();
  }

  public static String createAsicDataObjectReferenceXmlElement(String mimeType, String uri, String... content) {
    StringBuilder sb = new StringBuilder("<asic:DataObjectReference");
    if (mimeType != null) {
      sb.append(" MimeType=\"").append(mimeType).append('"');
    }
    if (uri != null) {
      sb.append(" URI=\"").append(uri).append('"');
    }
    if (ArrayUtils.isEmpty(content)) {
      return sb.append("/>").toString();
    }
    sb.append('>');
    for (String s : content) {
      sb.append(s);
    }
    return sb.append("</asic:DataObjectReference>").toString();
  }

  private AsicManifestTestUtils() {
  }

}
