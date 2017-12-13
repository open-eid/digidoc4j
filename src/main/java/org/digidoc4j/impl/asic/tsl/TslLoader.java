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

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.Protocol;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;

public class TslLoader implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(TslLoader.class);
  public static final File fileCacheDirectory = new File(System.getProperty("java.io.tmpdir") + "/digidoc4jTSLCache");
  private boolean checkSignature = true;
  private Configuration configuration;
  private transient TSLRepository tslRepository;
  private transient TSLCertificateSourceImpl tslCertificateSource;
  private transient TSLValidationJob tslValidationJob;

  private static final String DEFAULT_KEYSTORE_TYPE = "JKS";

  public TslLoader(Configuration configuration) {
    this.configuration = configuration;
  }

  public void prepareTsl() {
    try {
      tslCertificateSource = new TSLCertificateSourceImpl();
      tslRepository = new TSLRepository();
      tslRepository.setTrustedListsCertificateSource(tslCertificateSource);
      tslValidationJob = createTslValidationJob(tslRepository);
    } catch (DSSException e) {
      logger.error("Unable to load TSL: " + e.getMessage());
      throw new TslCertificateSourceInitializationException(e.getMessage());
    }
  }

  public static void invalidateCache() {
    logger.info("Cleaning TSL cache directory at " + fileCacheDirectory.getPath());
    try {
      if (fileCacheDirectory.exists()) {
        FileUtils.cleanDirectory(fileCacheDirectory);
      } else {
        logger.debug("TSL cache directory doesn't exist");
      }
    } catch (Exception e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

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

  private TSLValidationJob createTslValidationJob(TSLRepository tslRepository) {
    TSLValidationJob tslValidationJob = new TSLValidationJob();
    tslValidationJob.setDataLoader(createDataLoader());
    tslValidationJob.setOjContentKeyStore(getKeyStore());
    tslValidationJob.setLotlUrl(configuration.getTslLocation());
    tslValidationJob.setLotlCode("EU");
    tslValidationJob.setRepository(tslRepository);
    tslValidationJob.setCheckLOTLSignature(checkSignature);
    tslValidationJob.setCheckTSLSignatures(checkSignature);
    tslValidationJob.setFilterTerritories(configuration.getTrustedTerritories());
    //tslValidationJob.setLotlRootSchemeInfoUri("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl.html");
    return tslValidationJob;
  }

  private DataLoader createDataLoader() {
    if (Protocol.isHttpUrl(configuration.getTslLocation())) {
      CachingDataLoader dataLoader = new CachingDataLoader(configuration);
      dataLoader.setTimeoutConnection(configuration.getConnectionTimeout());
      dataLoader.setTimeoutSocket(configuration.getSocketTimeout());
      dataLoader.setCacheExpirationTime(configuration.getTslCacheExpirationTime());
      dataLoader.setFileCacheDirectory(fileCacheDirectory);

      logger.debug("Using file cache directory for storing TSL: " + fileCacheDirectory);
      return dataLoader;
    } else {
      return new CommonsDataLoader();
    }
  }

  private KeyStoreCertificateSource getKeyStore() {
    File tslKeystoreFile = getTslKeystoreFile();
    try {
      return new KeyStoreCertificateSource(tslKeystoreFile, DEFAULT_KEYSTORE_TYPE, configuration.getTslKeyStorePassword());
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new TslKeyStoreNotFoundException(e.getMessage());
    }
  }

  private File getTslKeystoreFile() throws TslKeyStoreNotFoundException {
    try {
      String keystoreLocation = configuration.getTslKeyStoreLocation();
      if (Files.exists(Paths.get(keystoreLocation))) {
        return new File(keystoreLocation);
      }
      File tempFile = File.createTempFile("temp-tsl-keystore", ".jks");
      InputStream in = getClass().getClassLoader().getResourceAsStream(keystoreLocation);
      if (in == null) {
        logger.error("keystore not found in location " + keystoreLocation);
        throw new TslKeyStoreNotFoundException("keystore not found in location " + keystoreLocation);
      }
      FileUtils.copyInputStreamToFile(in, tempFile);
      return tempFile;
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new TslKeyStoreNotFoundException(e.getMessage());
    }
  }

}
