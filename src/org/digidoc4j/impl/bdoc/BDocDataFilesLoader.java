/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import static org.digidoc4j.impl.bdoc.ManifestValidator.MANIFEST_PATH;
import static org.digidoc4j.impl.bdoc.ManifestValidator.MIMETYPE_PATH;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.DuplicateDataFileException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class BDocDataFilesLoader {

  private final static Logger logger = LoggerFactory.getLogger(BDocDataFilesLoader.class);
  private Map<String, DataFile> dataFiles = new LinkedHashMap<>();
  private List<DSSDocument> detachedContents;
  private Map<String, ManifestEntry> manifestFileItems;

  public BDocDataFilesLoader(SignedDocumentValidator validator) {
    detachedContents = validator.getDetachedContents();
  }

  public Map<String, DataFile> loadDataFiles() {
    loadManifestFileItems();
    for(DSSDocument doc: detachedContents) {
      String fileName = doc.getName();
      if (!MIMETYPE_PATH.equals(fileName) && !MANIFEST_PATH.equals(fileName)) {
        addDataFile(doc);
      }
    }
    return dataFiles;
  }

  private void loadManifestFileItems() {
    ManifestParser manifestParser = ManifestParser.findAndOpenManifestFile(detachedContents);
    manifestFileItems = manifestParser.getManifestFileItems();
  }

  private void addDataFile(DSSDocument doc) {
    validateNoDuplicateFile(doc.getName());
    String mimeType = getMimeType(doc);
    DataFile dataFile = new DataFile(doc.getBytes(), doc.getName(), mimeType);
    dataFiles.put(doc.getName(), dataFile);
  }

  private void validateNoDuplicateFile(String fileName) {
    if(dataFiles.containsKey(fileName)) {
      String errorMessage = "Data file " + fileName + " already exists";
      logger.error(errorMessage);
      throw new DuplicateDataFileException(errorMessage);
    }
  }

  private String getMimeType(DSSDocument document) {
    ManifestEntry manifestEntry = manifestFileItems.get(document.getName());
    if(manifestEntry != null) {
      return manifestEntry.getMimeType();
    } else {
      return document.getMimeType().getMimeTypeString();
    }
  }
}
