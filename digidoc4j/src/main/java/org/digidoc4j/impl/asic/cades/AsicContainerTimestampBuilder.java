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
import org.apache.commons.collections4.CollectionUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.Timestamp;
import org.digidoc4j.TimestampBuilder;
import org.digidoc4j.exceptions.DataFileMissingException;
import org.digidoc4j.impl.asic.AsicContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * An abstract base class for timestamp builders for ASiC containers.
 */
public abstract class AsicContainerTimestampBuilder extends TimestampBuilder {

  private static final Logger log = LoggerFactory.getLogger(AsicContainerTimestampBuilder.class);

  @Override
  protected Configuration getConfiguration() {
    return getContainer().getConfiguration();
  }

  @Override
  protected void ensureTimestampingIsPossible() {
    if (CollectionUtils.isEmpty(getContainer().getDataFiles())) {
      throw new DataFileMissingException();
    }
  }

  @Override
  protected AsicContainerTimestamp invokeTimestampingProcess() {
    List<UpdateableTimestampDocumentsHolder> existingTimestamps = collectExistingTimestamps();
    AsicContainerTimestampFinalizer timestampFinalizer = createTimestampFinalizer();
    return timestampFinalizer.finalizeTimestamp(existingTimestamps);
  }

  protected abstract AsicContainerTimestampFinalizer createTimestampFinalizer();

  protected abstract AsicContainerTimestamp createUpdatedTimestamp(AsicContainerTimestamp oldTimestamp, DSSDocument newContent);

  protected abstract AsicContainer getContainer();

  private List<UpdateableTimestampDocumentsHolder> collectExistingTimestamps() {
    List<Timestamp> containerTimestamps = getContainer().getTimestamps();

    if (CollectionUtils.isEmpty(containerTimestamps)) {
      return Collections.emptyList();
    }

    List<UpdateableTimestampDocumentsHolder> timestampDocumentsHolders = new ArrayList<>();

    for (Timestamp timestamp : containerTimestamps) {
      if (timestamp instanceof AsicContainerTimestamp) {
        timestampDocumentsHolders.add(asTimestampDocumentsHolder((AsicContainerTimestamp) timestamp));
      } else {
        log.warn("Not an ASiC timestamp: {}", timestamp.getUniqueId());
      }
    }

    return timestampDocumentsHolders;
  }

  private UpdateableTimestampDocumentsHolder asTimestampDocumentsHolder(AsicContainerTimestamp timestamp) {
    UpdateableTimestampDocumentsHolder timestampDocumentsHolder = new UpdateableTimestampDocumentsHolder();
    timestampDocumentsHolder.setTimestampDocument(timestamp.getCadesTimestamp().getTimestampDocument());

    if (timestamp.getArchiveManifest() != null) {
      timestampDocumentsHolder.setManifestDocument(timestamp.getArchiveManifest().getManifestDocument());
    }

    timestampDocumentsHolder.setTimestampDocumentOverrideListener(contentDocument ->
            replaceContainerTimestampContent(timestamp, contentDocument));

    return timestampDocumentsHolder;
  }

  private void replaceContainerTimestampContent(AsicContainerTimestamp oldTimestamp, DSSDocument newContentDocument) {
    AsicContainerTimestamp newTimestamp = createUpdatedTimestamp(oldTimestamp, newContentDocument);

    Container container = getContainer();
    container.removeTimestamp(oldTimestamp);
    container.addTimestamp(newTimestamp);
  }

}
