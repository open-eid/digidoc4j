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

import eu.europa.esig.dss.DSSDocument;

public class AsicEntry implements Serializable {

  private String name;
  private String comment;
  private byte[] extraFieldData;
  private DSSDocument content;
  private boolean isSignature;

  public AsicEntry(ZipEntry zipEntry) {
    name = zipEntry.getName();
    comment = zipEntry.getComment();
    extraFieldData = zipEntry.getExtra();
  }

  public DSSDocument getContent() {
    return content;
  }

  public void setContent(DSSDocument content) {
    this.content = content;
  }

  public ZipEntry getZipEntry() {
    ZipEntry entry = new ZipEntry(name);
    entry.setComment(comment);
    entry.setExtra(extraFieldData);
    return entry;
  }

  public boolean isSignature() {
    return isSignature;
  }

  public void setSignature(boolean signature) {
    isSignature = signature;
  }
}
