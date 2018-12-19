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

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DomUtils;

public class ManifestParser implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(ManifestParser.class);
  private static final String NAMESPACE = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
  private DSSDocument manifestFile;
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
    entries = new HashMap<>();
    loadFileEntriesFromManifest();
    return entries;
  }

  private void loadFileEntriesFromManifest() {
    Element root = loadManifestXml();
    Node firstChild = root.getFirstChild();
    while (firstChild != null) {
      String nodeName = firstChild.getLocalName();
      if ("file-entry".equals(nodeName)) {
        addFileEntry(firstChild);
      }
      firstChild = firstChild.getNextSibling();
    }
  }

  private Element loadManifestXml() {
    return DomUtils.buildDOM(manifestFile).getDocumentElement();
  }

  private void addFileEntry(Node firstChild) {
    NamedNodeMap attributes = firstChild.getAttributes();
    String filePath = attributes.getNamedItemNS(NAMESPACE, "full-path").getTextContent();
    String mimeType = attributes.getNamedItemNS(NAMESPACE, "media-type").getTextContent();
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
}
