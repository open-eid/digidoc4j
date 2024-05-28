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
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.TimestampParameters;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.AbstractFinalizer;
import org.digidoc4j.impl.AiaSourceFactory;
import org.digidoc4j.impl.CommonOCSPSource;
import org.digidoc4j.impl.OcspDataLoaderFactory;
import org.digidoc4j.impl.TspDataLoaderFactory;
import org.digidoc4j.impl.asic.DetachedContentCreator;

import java.util.List;

/**
 * Base class for finalizers of timestamp tokens for ASiC containers.
 */
public abstract class AsicContainerTimestampFinalizer extends AbstractFinalizer {

  protected final CadesTimestampingDssFacade timestampingFacade;

  /**
   * Creates an instance of timestamp finalizer with specified configuration, datafile and timestamp parameters.
   *
   * @param configuration configuration to be used for timestamp finalization
   * @param dataFiles datafile to timestamp
   * @param timestampParameters timestamp parameters
   */
  protected AsicContainerTimestampFinalizer(
          Configuration configuration,
          List<DataFile> dataFiles,
          TimestampParameters timestampParameters
  ) {
    super(configuration, dataFiles);
    timestampingFacade = new CadesTimestampingDssFacade();
    configureTimestampingFacade(timestampParameters);
  }

  /**
   * Finalize and return a new timestamp based on the state of this finalizer and an optional list of existing
   * timestamp tokens.
   * Existing timestamp tokens, if any, will also be covered by the new timestamp token that this finalizer will create.
   * NB: finalization process <b>may</b> also <b>augment</b> (some of) the existing timestamps presented in the list of
   * {@code existingTimestamps}.
   * NB: in case of using the same finalizer instance for creating multiple timestamps, each call to this method
   * <b>must</b> provide an updated argument to {@code existingTimestamps} (reflecting the changes caused by previous
   * calls to this method).
   *
   * @param existingTimestamps optional list of existing timestamp tokens to take into account when creating a new
   * timestamp
   * @return newly created timestamp token for ASiC containers
   */
  public AsicContainerTimestamp finalizeTimestamp(List<UpdateableTimestampDocumentsHolder> existingTimestamps) {
    List<DSSDocument> dataFileDocuments = getDataFileDocuments();
    TimestampDocumentsHolder timestampDocumentsHolder = timestampingFacade.timestampContent(dataFileDocuments, existingTimestamps);
    return createAsicContainerTimestamp(timestampDocumentsHolder);
  }

  /**
   * Creates an instance of {@link AsicContainerTimestamp} from the specified timestamp documents.
   *
   * @param timestampDocumentsHolder collection of raw documents of the timestamp to create
   * @return timestamp for ASiC containers created from the specified documents
   */
  protected abstract AsicContainerTimestamp createAsicContainerTimestamp(TimestampDocumentsHolder timestampDocumentsHolder);

  private void configureTimestampingFacade(TimestampParameters timestampParameters) {
    timestampingFacade.setTimestampDigestAlgorithm(timestampParameters.getTimestampDigestAlgorithm());
    timestampingFacade.setReferenceDigestAlgorithm(timestampParameters.getReferenceDigestAlgorithm());

    timestampingFacade.setAiaSource(createAiaSource());
    timestampingFacade.setCertificateSource(configuration.getTSL());
    timestampingFacade.setOcspSource(createOcspSource());
    timestampingFacade.setTspSource(createTspSource(timestampParameters.getTspSource()));
  }

  private AIASource createAiaSource() {
    return new AiaSourceFactory(configuration).create();
  }

  private OCSPSource createOcspSource() {
    CommonOCSPSource ocspSource = new CommonOCSPSource(configuration);
    DataLoader dataLoader = new OcspDataLoaderFactory(configuration).create();
    ocspSource.setDataLoader(dataLoader);
    return ocspSource;
  }

  private TSPSource createTspSource(String tspSourceUrl) {
    OnlineTSPSource tspSource = new OnlineTSPSource(tspSourceUrl);
    DataLoader dataLoader = new TspDataLoaderFactory(configuration).create();
    tspSource.setDataLoader(dataLoader);
    return tspSource;
  }

  private List<DSSDocument> getDataFileDocuments() {
    try {
      return new DetachedContentCreator().populate(dataFiles).getDetachedContentList();
    } catch (Exception e) {
      throw new TechnicalException("Failed to extract documents of data files", e);
    }
  }

}
