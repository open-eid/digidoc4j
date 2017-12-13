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

import eu.europa.esig.dss.DSSDocument;

public class DetachedContentCreator {

  private DSSDocument firstDetachedContent;
  private List<DSSDocument> detachedContentList;

  public DetachedContentCreator populate(Collection<DataFile> dataFiles) {
    detachedContentList = new ArrayList<>(dataFiles.size());
    if(dataFiles.isEmpty()) {
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

  public List<DSSDocument> getDetachedContentList() {
    return detachedContentList;
  }

  public DSSDocument getFirstDetachedContent() {
    return firstDetachedContent;
  }
}
