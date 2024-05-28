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

import eu.europa.esig.dss.model.DSSDocument;

/**
 * A mutable holder for DSSDocuments of a timestamp token and its optional manifest.
 */
public class TimestampDocumentsHolder {

  private DSSDocument timestampDocument;
  private DSSDocument manifestDocument;

  public TimestampDocumentsHolder() {}

  public TimestampDocumentsHolder(DSSDocument timestampDocument) {
    setTimestampDocument(timestampDocument);
  }

  public DSSDocument getTimestampDocument() {
    return timestampDocument;
  }

  public void setTimestampDocument(DSSDocument timestampDocument) {
    this.timestampDocument = timestampDocument;
  }

  public DSSDocument getManifestDocument() {
    return manifestDocument;
  }

  public void setManifestDocument(DSSDocument manifestDocument) {
    this.manifestDocument = manifestDocument;
  }

}
