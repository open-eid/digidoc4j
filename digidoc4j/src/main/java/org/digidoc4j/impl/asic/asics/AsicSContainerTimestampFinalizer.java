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

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.DataFile;
import org.digidoc4j.TimestampParameters;
import org.digidoc4j.impl.asic.cades.AsicArchiveManifest;
import org.digidoc4j.impl.asic.cades.AsicContainerTimestampFinalizer;
import org.digidoc4j.impl.asic.cades.CadesTimestamp;
import org.digidoc4j.impl.asic.cades.TimestampDocumentsHolder;

import java.util.Collections;

/**
 * An implementation of a finalizer for timestamp tokens for ASiC-S containers.
 */
public class AsicSContainerTimestampFinalizer extends AsicContainerTimestampFinalizer {

  /**
   * Creates an instance of timestamp finalizer with specified configuration, datafile and timestamp parameters.
   *
   * @param configuration configuration to be used for timestamp finalization
   * @param dataFile datafile to timestamp
   * @param timestampParameters timestamp parameters
   */
  public AsicSContainerTimestampFinalizer(
          Configuration configuration,
          DataFile dataFile,
          TimestampParameters timestampParameters
  ) {
    super(configuration, Collections.singletonList(dataFile), timestampParameters);
    timestampingFacade.setContainerType(Container.DocumentType.ASICS);
  }

  @Override
  protected AsicSContainerTimestamp createAsicContainerTimestamp(TimestampDocumentsHolder timestampDocumentsHolder) {
    CadesTimestamp cadesTimestamp = new CadesTimestamp(timestampDocumentsHolder.getTimestampDocument());
    if (timestampDocumentsHolder.getManifestDocument() != null) {
      AsicArchiveManifest asicArchiveManifest = new AsicArchiveManifest(timestampDocumentsHolder.getManifestDocument());
      return new AsicSContainerTimestamp(cadesTimestamp, asicArchiveManifest);
    } else {
      return new AsicSContainerTimestamp(cadesTimestamp);
    }
  }

}
