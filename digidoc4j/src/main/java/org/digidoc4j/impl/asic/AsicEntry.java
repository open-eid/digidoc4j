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

import java.io.Serializable;
import java.util.zip.ZipEntry;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * ASIC entry
 */
public class AsicEntry implements Serializable {

  private String name;
  private String comment;
  private byte[] extraFieldData;
  private DSSDocument content;
  private boolean isSignature;

  /**
   * @param zipEntry entry
   */
  public AsicEntry(ZipEntry zipEntry) {
    name = zipEntry.getName();
    comment = zipEntry.getComment();
    extraFieldData = zipEntry.getExtra();
  }

  /**
   * @return name
   */
  public String getName() {
    return name;
  }

  /**
   * @return DSS document
   */
  public DSSDocument getContent() {
    return content;
  }

  /**
   * @param content DSS document
   */
  public void setContent(DSSDocument content) {
    this.content = content;
  }

  /**
   * @return entry
   */
  public ZipEntry getZipEntry() {
    ZipEntry entry = new ZipEntry(name);
    entry.setComment(comment);
    entry.setExtra(extraFieldData);
    return entry;
  }

  /**
   * @return indication whether it's a signature
   */
  public boolean isSignature() {
    return isSignature;
  }

  /**
   * @param signature signature flag
   */
  public void setSignature(boolean signature) {
    isSignature = signature;
  }

}
