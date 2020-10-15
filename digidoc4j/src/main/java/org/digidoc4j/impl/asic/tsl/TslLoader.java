/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.tsl;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.alerts.TLAlert;
import eu.europa.esig.dss.tsl.alerts.detections.TLExpirationDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLSignatureErrorDetection;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLExpirationAlertHandler;
import eu.europa.esig.dss.tsl.alerts.handlers.log.LogTLSignatureErrorAlertHandler;
import eu.europa.esig.dss.tsl.function.EULOTLOtherTSLPointer;
import eu.europa.esig.dss.tsl.function.SchemeTerritoryOtherTSLPointer;
import eu.europa.esig.dss.tsl.function.XMLOtherTSLPointer;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.FileUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TslCertificateSourceInitializationException;
import org.digidoc4j.exceptions.TslKeyStoreNotFoundException;
import org.digidoc4j.utils.ResourceUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * TSL loader
 */
public class TslLoader implements Serializable {

  public static final File fileCacheDirectory = new File(System.getProperty("java.io.tmpdir") + "/digidoc4jTSLCache");
  private static final Logger logger = LoggerFactory.getLogger(TslLoader.class);
  private static final String DEFAULT_KEYSTORE_TYPE = "JKS";
  private transient TSLCertificateSourceImpl tslCertificateSource;
  private transient TLValidationJob tlValidationJob;
  private final Configuration configuration;

  /**
   * @param configuration configuration context
   */
  public TslLoader(Configuration configuration) {
    this.configuration = configuration;
  }

  public static void invalidateCache() {
    logger.info("Cleaning TSL cache directory at {}", TslLoader.fileCacheDirectory.getPath());
    try {
      if (TslLoader.fileCacheDirectory.exists()) {
        FileUtils.cleanDirectory(TslLoader.fileCacheDirectory);
      } else {
        logger.debug("TSL cache directory doesn't exist");
      }
    } catch (Exception e) {
      throw new DigiDoc4JException(e);
    }
  }

  public void prepareTsl() {
    try {
      this.tslCertificateSource = new TSLCertificateSourceImpl();
      this.tlValidationJob = this.createTslValidationJob();
    } catch (DSSException e) {
      throw new TslCertificateSourceInitializationException("Failed to initialize TSL: " + e.getMessage(), e);
    }
  }

  private TLValidationJob createTslValidationJob() {
    TLValidationJob job = new TLValidationJob();

    DataLoader tslDataLoader = new TslDataLoaderFactory(this.configuration, fileCacheDirectory).create();
    if (tslDataLoader instanceof DSSFileLoader) {
      job.setOnlineDataLoader((DSSFileLoader) tslDataLoader);
    } else {
      job.setOnlineDataLoader(new FileCacheDataLoader(tslDataLoader));
    }
    LOTLSource lotlSource = createLOTLSource();
    job.setListOfTrustedListSources(lotlSource);
    job.setTrustedListCertificateSource(this.tslCertificateSource);
    job.setSynchronizationStrategy(new AcceptAllStrategy());

    job.setTLAlerts(Arrays.asList(tlSigningAlert(), tlExpirationDetection()));

    return job;
  }

  public TLAlert tlSigningAlert() {
    TLSignatureErrorDetection signingDetection = new TLSignatureErrorDetection();
    LogTLSignatureErrorAlertHandler handler = new LogTLSignatureErrorAlertHandler();
    return new TLAlert(signingDetection, handler);
  }

  public TLAlert tlExpirationDetection() {
    TLExpirationDetection expirationDetection = new TLExpirationDetection();
    LogTLExpirationAlertHandler handler = new LogTLExpirationAlertHandler();
    return new TLAlert(expirationDetection, handler);
  }

  private LOTLSource createLOTLSource() {
    LOTLSource lotlSource = new LOTLSource();
    lotlSource.setUrl(this.configuration.getTslLocation());
    lotlSource.setCertificateSource(this.tslCertificateSource);

    lotlSource.setCertificateSource(getKeyStore());
    Set<String> trustedTerritories = new HashSet<>();
    CollectionUtils.addAll(trustedTerritories, this.configuration.getTrustedTerritories());

    lotlSource.setLotlPredicate(new EULOTLOtherTSLPointer()
            .and(new XMLOtherTSLPointer())
            .and(new SchemeTerritoryOtherTSLPointer(trustedTerritories))
    );
    lotlSource.setPivotSupport(true);

    return lotlSource;
  }


  private KeyStoreCertificateSource getKeyStore() {
    try (InputStream tslKeyStoreInputStream = openTslKeyStoreInputStream()) {
      return new KeyStoreCertificateSource(tslKeyStoreInputStream, DEFAULT_KEYSTORE_TYPE,
              this.configuration.getTslKeyStorePassword());
    } catch (IOException e) {
      throw new TslKeyStoreNotFoundException("Unable to retrieve keystore", e);
    }
  }

  private InputStream openTslKeyStoreInputStream() throws IOException, TslKeyStoreNotFoundException {
    String keystoreLocation = this.configuration.getTslKeyStoreLocation();
    if (ResourceUtils.isFileReadable(keystoreLocation)) {
      return new FileInputStream(keystoreLocation);
    }
    InputStream in = getClass().getClassLoader().getResourceAsStream(keystoreLocation);
    if (in == null) {
      throw new TslKeyStoreNotFoundException("Unable to retrieve TSL keystore", new RuntimeException(String.format
              ("Keystore not found by location <%s>", keystoreLocation)));
    }
    return in;
  }

  /*
   * ACCESSORS
   */


  public TSLCertificateSourceImpl getTslCertificateSource() {
    return tslCertificateSource;
  }

  public TLValidationJob getTlValidationJob() {
    return tlValidationJob;
  }

}
