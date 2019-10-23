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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.TslCertificateSourceInitializationException;
import org.digidoc4j.exceptions.TslKeyStoreNotFoundException;
import org.digidoc4j.impl.asic.CachingDataLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;

/**
 * TSL loader
 */
public class TslLoader implements Serializable {

  public static final File fileCacheDirectory = new File(System.getProperty("java.io.tmpdir") + "/digidoc4jTSLCache");
  private static final Logger logger = LoggerFactory.getLogger(TslLoader.class);
  private static final String DEFAULT_KEYSTORE_TYPE = "JKS";
  private transient TSLRepository tslRepository;
  private transient TSLCertificateSourceImpl tslCertificateSource;
  private transient TSLValidationJob tslValidationJob;
  private Configuration configuration;
  private boolean checkSignature = true;

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
      this.tslRepository = new TSLRepository();
      this.tslRepository.setTrustedListsCertificateSource(this.tslCertificateSource);
      this.tslValidationJob = this.createTslValidationJob(this.tslRepository);
    } catch (DSSException e) {
      throw new TslCertificateSourceInitializationException("Failed to initialize TSL: " + e.getMessage(), e);
    }
  }

  private TSLValidationJob createTslValidationJob(TSLRepository repository) {
    TSLValidationJob job = new TSLValidationJob();
    job.setDataLoader(this.createDataLoader());
    job.setOjContentKeyStore(this.getKeyStore());
    job.setLotlUrl(this.configuration.getTslLocation());
    job.setLotlCode("EU");
    job.setRepository(repository);
    job.setCheckLOTLSignature(this.checkSignature);
    job.setCheckTSLSignatures(this.checkSignature);
    job.setOjUrl("");
    job.setFilterTerritories(this.configuration.getTrustedTerritories());
    return job;
  }

  private DataLoader createDataLoader() {
    if (Protocol.isHttpUrl(this.configuration.getTslLocation())) {
      CachingDataLoader dataLoader = new CachingDataLoader(this.configuration);
      dataLoader.setTimeoutConnection(this.configuration.getConnectionTimeout());
      dataLoader.setTimeoutSocket(this.configuration.getSocketTimeout());
      dataLoader.setCacheExpirationTime(this.configuration.getTslCacheExpirationTime());
      dataLoader.setFileCacheDirectory(this.fileCacheDirectory);
      logger.debug("Using file cache directory for storing TSL: {}", this.fileCacheDirectory);
      return dataLoader;
    } else {
      return new CommonsDataLoader();
    }
  }

  private KeyStoreCertificateSource getKeyStore() {
    File tslKeystoreFile = this.getTslKeystoreFile();
    try {
      return new KeyStoreCertificateSource(tslKeystoreFile, DEFAULT_KEYSTORE_TYPE,
          this.configuration.getTslKeyStorePassword());
    } catch (IOException e) {
      throw new TslKeyStoreNotFoundException("Unable to retrieve keystore", e);
    }
  }

  private File getTslKeystoreFile() throws TslKeyStoreNotFoundException {
    try {
      String keystoreLocation = this.configuration.getTslKeyStoreLocation();
      if (Files.exists(Paths.get(keystoreLocation))) {
        return new File(keystoreLocation);
      }
      File tempFile = File.createTempFile("temp-tsl-keystore", ".jks");
      InputStream in = getClass().getClassLoader().getResourceAsStream(keystoreLocation);
      if (in == null) {
        throw new TslKeyStoreNotFoundException("Unable to retrieve TSL keystore", new RuntimeException(String.format
            ("Keystore not found by location <%s>", keystoreLocation)));
      }
      FileUtils.copyInputStreamToFile(in, tempFile);
      return tempFile;
    } catch (IOException e) {
      throw new TslKeyStoreNotFoundException("Unable to retrieve TSL keystore", e);
    }
  }

  /*
   * ACCESSORS
   */

  public void setCheckSignature(boolean checkSignature) {
    this.checkSignature = checkSignature;
  }

  public TSLCertificateSourceImpl getTslCertificateSource() {
    return tslCertificateSource;
  }

  public TSLValidationJob getTslValidationJob() {
    return tslValidationJob;
  }

  public TSLRepository getTslRepository() {
    return tslRepository;
  }

}
