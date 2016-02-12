/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.asic;

import java.io.Serializable;
import java.util.List;

import org.digidoc4j.DataFile;
import org.digidoc4j.impl.bdoc.manifest.ManifestParser;

import eu.europa.esig.dss.DSSDocument;

public class AsicParseResult implements Serializable {

  private List<DSSDocument> signatures;
  private List<DataFile> dataFiles;
  private List<DSSDocument> detachedContents;
  private DSSDocument detachedContent;
  private Integer currentUsedSignatureFileIndex;
  private String zipFileComment;
  private List<AsicEntry> asicEntries;
  private ManifestParser manifestParser;

  public List<DataFile> getDataFiles() {
    return dataFiles;
  }

  public void setDataFiles(List<DataFile> dataFiles) {
    this.dataFiles = dataFiles;
  }

  public List<DSSDocument> getSignatures() {
    return signatures;
  }

  public void setSignatures(List<DSSDocument> signatures) {
    this.signatures = signatures;
  }

  public List<DSSDocument> getDetachedContents() {
    return detachedContents;
  }

  public void setDetachedContents(List<DSSDocument> detachedContents) {
    this.detachedContents = detachedContents;
  }

  public DSSDocument getDetachedContent() {
    return detachedContent;
  }

  public void setDetachedContent(DSSDocument detachedContent) {
    this.detachedContent = detachedContent;
  }

  public Integer getCurrentUsedSignatureFileIndex() {
    return currentUsedSignatureFileIndex;
  }

  public void setCurrentUsedSignatureFileIndex(Integer currentUsedSignatureFileIndex) {
    this.currentUsedSignatureFileIndex = currentUsedSignatureFileIndex;
  }

  public String getZipFileComment() {
    return zipFileComment;
  }

  public void setZipFileComment(String zipFileComment) {
    this.zipFileComment = zipFileComment;
  }

  public List<AsicEntry> getAsicEntries() {
    return asicEntries;
  }

  public void setAsicEntries(List<AsicEntry> asicEntries) {
    this.asicEntries = asicEntries;
  }

  public ManifestParser getManifestParser() {
    return manifestParser;
  }

  public void setManifestParser(ManifestParser manifestParser) {
    this.manifestParser = manifestParser;
  }
}
