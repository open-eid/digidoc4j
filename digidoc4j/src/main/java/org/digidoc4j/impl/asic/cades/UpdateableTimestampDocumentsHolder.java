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

import java.util.function.Consumer;

/**
 * A mutable holder that extends {@link TimestampDocumentsHolder}'s capability for holding timestamp documents
 * by adding a slot for holding a timestamp token document override listener.
 * The override listener enables to catch the events of timestamp token documents being overridden by timestamp
 * augmentation processes, and to update the original timestamp that encapsulates the timestamp token document in
 * question.
 */
public class UpdateableTimestampDocumentsHolder extends TimestampDocumentsHolder {

  private Consumer<DSSDocument> timestampDocumentOverrideListener;

  public void setTimestampDocumentOverrideListener(Consumer<DSSDocument> listener) {
    timestampDocumentOverrideListener = listener;
  }

  public Consumer<DSSDocument> getTimestampDocumentOverrideListener() {
    return timestampDocumentOverrideListener;
  }

}
