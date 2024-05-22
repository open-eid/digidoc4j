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

import eu.europa.esig.dss.model.DSSDocument;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.DataFile;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.impl.asic.cades.CadesTimestamp;
import org.digidoc4j.impl.asic.cades.ContainerTimestampWrapper;
import org.digidoc4j.impl.asic.manifest.ManifestParser;
import org.digidoc4j.impl.asic.xades.XadesSignatureWrapper;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * ASIC parse result
 */
public class AsicParseResult implements Serializable {

  private List<XadesSignatureWrapper> signatures;
  private List<DataFile> dataFiles;
  private List<DSSDocument> detachedContents;
  private Integer currentUsedSignatureFileIndex;
  private String zipFileComment;
  private List<AsicEntry> asicEntries;
  private ManifestParser manifestParser;
  private List<ContainerTimestampWrapper> timestamps;
  private String mimeType;

  /**
   * @return list of data files
   */
  public List<DataFile> getDataFiles() {
    return dataFiles;
  }

  /**
   * @param dataFiles list of data files
   */
  public void setDataFiles(List<DataFile> dataFiles) {
    this.dataFiles = dataFiles;
  }

  /**
   * @return list of signatures
   */
  public List<XadesSignatureWrapper> getSignatures() {
    return signatures;
  }
  /**
   * @param signatures list of signatures
   */
  public void setSignatures(List<XadesSignatureWrapper> signatures) {
    this.signatures = signatures;
  }

  public boolean removeSignature(String signatureName) {
    for (XadesSignatureWrapper signatureWrapper : signatures) {
      if (StringUtils.equalsIgnoreCase(signatureWrapper.getSignatureDocument().getName(), signatureName)) {
        return signatures.remove(signatureWrapper);
      }
    }
    return false;
  }

  /**
   * @return list of detached content
   */
  public List<DSSDocument> getDetachedContents() {
    return detachedContents;
  }

  public void setDetachedContents(List<DSSDocument> detachedContents) {
    this.detachedContents = detachedContents;
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

  public boolean removeAsicEntry(String asicEntryName) {
    for (AsicEntry asicEntry : asicEntries) {
      if (StringUtils.equalsIgnoreCase(asicEntry.getZipEntry().getName(), asicEntryName)) {
        return asicEntries.remove(asicEntry);
      }
    }
    return false;
  }

  public ManifestParser getManifestParser() {
    return manifestParser;
  }

  public void setManifestParser(ManifestParser manifestParser) {
    this.manifestParser = manifestParser;
  }

  public List<ContainerTimestampWrapper> getTimestamps() {
    return timestamps;
  }

  public void setTimestamps(List<ContainerTimestampWrapper> timestamps) {
    this.timestamps = timestamps;
  }

  public boolean removeTimestamp(String timestampName) {
    for (ContainerTimestampWrapper timestamp : timestamps) {
      if (StringUtils.equals(timestamp.getCadesTimestamp().getTimestampDocument().getName(), timestampName)) {
        return timestamps.remove(timestamp);
      }
    }
    return false;
  }

  @Deprecated
  public void setTimeStampToken(DataFile timeStampToken) {
    if (timeStampToken != null) {
      timestamps = new ArrayList<>(1);
      CadesTimestamp cadesTimestamp = new CadesTimestamp(timeStampToken.getDocument());
      timestamps.add(new ContainerTimestampWrapper(cadesTimestamp));
    } else {
      timestamps = null;
    }
  }

  @Deprecated
  public DataFile getTimeStampToken() {
    if (CollectionUtils.isEmpty(timestamps)) {
      return null;
    } else if (timestamps.size() == 1) {
      ContainerTimestampWrapper timestamp = timestamps.get(0);
      if (timestamp.getArchiveManifest() != null) {
        throw new NotSupportedException("There is a manifest bound to the timestamp. Use getTimestamps() instead.");
      }
      DataFile dataFile = new DataFile();
      dataFile.setDocument(timestamp.getCadesTimestamp().getTimestampDocument());
      return dataFile;
    }
    throw new NotSupportedException("Parse result contains more than 1 timestamp. Use getTimestamps() instead.");
  }

  public void setMimeType(String mimeType) {
    this.mimeType = mimeType;
  }

  public String getMimeType() {
    return mimeType;
  }
}
