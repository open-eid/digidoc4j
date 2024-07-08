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
import org.digidoc4j.Container;
import org.digidoc4j.DataFile;
import org.digidoc4j.Timestamp;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.DetachedContentCreator;
import org.digidoc4j.impl.asic.cades.CadesValidationDssFacade;
import org.digidoc4j.impl.asic.cades.CadesValidationReportGenerator;
import org.digidoc4j.impl.asic.cades.TimestampAndManifestPair;
import org.digidoc4j.impl.asic.cades.TimestampDocumentsHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Validation report generator for ASiC-S containers with timestamp tokens.
 */
public class AsicSTimestampsValidationReportGenerator extends CadesValidationReportGenerator {

  private static final Logger log = LoggerFactory.getLogger(AsicSTimestampsValidationReportGenerator.class);

  private final AsicSContainer asicsContainer;

  public AsicSTimestampsValidationReportGenerator(AsicSContainer asicsContainer) {
    super(asicsContainer.getConfiguration());
    this.asicsContainer = asicsContainer;
  }

  @Override
  protected void configureValidationFacade(CadesValidationDssFacade validationDssFacade) {
    validationDssFacade.setContainerType(Container.DocumentType.ASICS);
    validationDssFacade.setDataFiles(extractDataFilesDocuments(asicsContainer.getDataFiles()));
    validationDssFacade.setTimestamps(extractTimestampsDocuments(asicsContainer.getTimestamps()));
  }

  private static List<DSSDocument> extractDataFilesDocuments(List<DataFile> dataFiles) {
    try {
      return new DetachedContentCreator().populate(dataFiles).getDetachedContentList();
    } catch (Exception e) {
      throw new TechnicalException("Failed to extract documents of data files", e);
    }
  }

  private static List<TimestampDocumentsHolder> extractTimestampsDocuments(List<Timestamp> timestamps) {
    List<TimestampDocumentsHolder> timestampDocumentsHolders = new ArrayList<>();

    for (Timestamp timestamp : timestamps) {
      if (timestamp instanceof TimestampAndManifestPair) {
        timestampDocumentsHolders.add(extractTimestampDocuments((TimestampAndManifestPair) timestamp));
      } else {
        log.warn("Unrecognizable timestamp type in ASiC-S container: {}", timestamp.getClass().getSimpleName());
      }
    }

    return timestampDocumentsHolders;
  }

  private static TimestampDocumentsHolder extractTimestampDocuments(TimestampAndManifestPair timestamp) {
    TimestampDocumentsHolder timestampDocumentsHolder = new TimestampDocumentsHolder();
    timestampDocumentsHolder.setTimestampDocument(timestamp.getCadesTimestamp().getTimestampDocument());
    if (timestamp.getArchiveManifest() != null) {
      timestampDocumentsHolder.setManifestDocument(timestamp.getArchiveManifest().getManifestDocument());
    }
    return timestampDocumentsHolder;
  }

}
