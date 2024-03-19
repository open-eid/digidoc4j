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

import eu.europa.esig.dss.asic.xades.definition.ManifestAttribute;
import eu.europa.esig.dss.asic.xades.definition.ManifestElement;
import eu.europa.esig.dss.asic.xades.definition.ManifestNamespace;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.xml.utils.DomUtils;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class ManifestParser implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(ManifestParser.class);

  private final DSSDocument manifestFile;
  private Map<String, ManifestEntry> entries;

  public ManifestParser(DSSDocument manifestFile) {
    this.manifestFile = manifestFile;
  }

  public boolean containsManifestFile() {
    return manifestFile != null;
  }

  public Map<String, ManifestEntry> getManifestFileItems() {
    if (!containsManifestFile()) {
      return Collections.emptyMap();
    }
    entries = new LinkedHashMap<>();
    loadFileEntriesFromManifest();
    return entries;
  }

  private void loadFileEntriesFromManifest() {
    Element root = loadManifestXml();
    Node childNode = root.getFirstChild();
    while (childNode != null) {
      String nodeName = childNode.getLocalName();
      if (ManifestElement.FILE_ENTRY.isSameTagName(nodeName)) {
        addFileEntry(childNode);
      }
      childNode = childNode.getNextSibling();
    }
  }

  private Element loadManifestXml() {
    return DomUtils.buildDOM(manifestFile).getDocumentElement();
  }

  private void addFileEntry(Node fileEntry) {
    String filePath = getNodeAttributeText(fileEntry, ManifestAttribute.FULL_PATH);
    String mimeType = getNodeAttributeText(fileEntry, ManifestAttribute.MEDIA_TYPE);
    if (!"/".equals(filePath)) {
      validateNotDuplicateFile(filePath);
      entries.put(filePath, new ManifestEntry(filePath, mimeType));
    }
  }

  private void validateNotDuplicateFile(String filePath) {
    if (entries.containsKey(filePath)) {
      DuplicateDataFileException digiDoc4JException = new DuplicateDataFileException("duplicate entry in manifest file: " + filePath);
      logger.error(digiDoc4JException.getMessage());
      throw digiDoc4JException;
    }
  }

  private static String getNodeAttributeText(Node node, ManifestAttribute attribute) {
    return node.getAttributes()
            .getNamedItemNS(ManifestNamespace.NS.getUri(), attribute.getAttributeName())
            .getTextContent();
  }

}
