/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.apache.commons.collections4.CollectionUtils;
import org.digidoc4j.Container;
import org.digidoc4j.exceptions.IllegalContainerContentException;
import org.digidoc4j.impl.asic.cades.AsicContainerTimestamp;
import org.digidoc4j.impl.asic.cades.AsicContainerTimestampBuilder;
import org.digidoc4j.impl.asic.cades.CadesTimestamp;

/**
 * An implementation of a timestamp builder for ASiC-S containers.
 */
public class AsicSContainerTimestampBuilder extends AsicContainerTimestampBuilder {

  private final AsicSContainer asicSContainer;

  /**
   * Creates an instance of the builder.
   *
   * @param container the container to build a timestamp for
   * @throws IllegalArgumentException if the container is not an instance of {@link AsicSContainer}
   */
  public AsicSContainerTimestampBuilder(Container container) {
    if (container instanceof AsicSContainer) {
      asicSContainer = (AsicSContainer) container;
    } else {
      throw new IllegalArgumentException("Not an ASiC-S container");
    }
  }

  @Override
  protected AsicSContainer getContainer() {
    return asicSContainer;
  }

  @Override
  protected void ensureTimestampingIsPossible() {
    if (CollectionUtils.isNotEmpty(getContainer().getSignatures())) {
      throw new IllegalContainerContentException("ASiC-S container containing signatures cannot be timestamped");
    }
    super.ensureTimestampingIsPossible();
    if (getContainer().getDataFiles().size() != 1) {
      throw new IllegalContainerContentException("ASiC-S container must contain exactly one datafile to be timestamped");
    }
  }

  @Override
  protected AsicSContainerTimestamp createUpdatedTimestamp(AsicContainerTimestamp oldTimestamp, DSSDocument newContent) {
    DSSDocument oldTimestampDocument = oldTimestamp.getCadesTimestamp().getTimestampDocument();
    CadesTimestamp newCadesTimestamp = new CadesTimestamp(new InMemoryDocument(
            newContent.openStream(),
            oldTimestampDocument.getName(),
            oldTimestampDocument.getMimeType()
    ));

    if (oldTimestamp.getArchiveManifest() != null) {
      return new AsicSContainerTimestamp(newCadesTimestamp, oldTimestamp.getArchiveManifest());
    } else {
      return new AsicSContainerTimestamp(newCadesTimestamp);
    }
  }

  @Override
  protected AsicSContainerTimestampFinalizer createTimestampFinalizer() {
    return new AsicSContainerTimestampFinalizer(
            getConfiguration(),
            asicSContainer.getDataFiles().get(0),
            this
    );
  }

}
