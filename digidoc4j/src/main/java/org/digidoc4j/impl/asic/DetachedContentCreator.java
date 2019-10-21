/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.digidoc4j.DataFile;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * Class for building list of detached content files.
 */
public class DetachedContentCreator {

  private DSSDocument firstDetachedContent;
  private List<DSSDocument> detachedContentList;

  /**
   * Method for generating list of detached content files from list of files.
   * @param dataFiles Files what should be signed
   * @return Creator object
   * @throws Exception
   */
  public DetachedContentCreator populate(Collection<DataFile> dataFiles) throws Exception {
    detachedContentList = new ArrayList<>(dataFiles.size());
    if (dataFiles.isEmpty()) {
      return this;
    }
    populateDetachedContent(dataFiles);
    return this;
  }

  private void populateDetachedContent(Collection<DataFile> dataFiles) {
    Iterator<DataFile> dataFileIterator = dataFiles.iterator();
    firstDetachedContent = dataFileIterator.next().getDocument();
    detachedContentList.add(firstDetachedContent);
    while (dataFileIterator.hasNext()) {
      DataFile dataFile = dataFileIterator.next();
      DSSDocument document = dataFile.getDocument();
      detachedContentList.add(document);
    }
  }

  /**
   * Method for asking detached content list
   * @return Detached content list
   */
  public List<DSSDocument> getDetachedContentList() {
    return detachedContentList;
  }

  /**
   * Method for asking first detached content file
   * @return First detached content file
   */
  public DSSDocument getFirstDetachedContent() {
    return firstDetachedContent;
  }
}
