/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.tsl;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.TSLCertificateSource;
import org.digidoc4j.exceptions.TslKeyStoreNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TslManager implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(TslManager.class);
  private TSLCertificateSource tslCertificateSource;
  private Configuration configuration;

  public TslManager(Configuration configuration) {
    this.configuration = configuration;
  }

  public TSLCertificateSource getTsl() {
    if (tslCertificateSource != null) {
      logger.debug("Using TSL cached copy");
      return tslCertificateSource;
    }
    loadTsl();
    return tslCertificateSource;
  }

  public void setTsl(TSLCertificateSource certificateSource) {
    this.tslCertificateSource = certificateSource;
  }

  /**
   * Loading TSL in a single thread in a synchronized block to avoid duplicate TSL loading by multiple threads.
   */
  private synchronized void loadTsl() {
    //Using double-checked locking to avoid other threads to start loading TSL
    if(tslCertificateSource == null) {
      logger.debug("Loading TSL in a synchronized block");
      String tslLocation = configuration.getTslLocation();
      File tslKeystoreFile = getTslKeystoreFile();
      String tslKeyStorePassword = configuration.getTslKeyStorePassword();

      TslLoader tslLoader = new TslLoader(tslLocation, tslKeystoreFile, tslKeyStorePassword);
      tslLoader.setCheckSignature(configuration.shouldValidateTslSignature());
      tslLoader.setConnectionTimeout(configuration.getConnectionTimeout());
      tslLoader.setSocketTimeout(configuration.getSocketTimeout());
      tslLoader.setCacheExpirationTime(configuration.getTslCacheExpirationTime());
      LazyTslCertificateSource lazyTsl = new LazyTslCertificateSource(tslLoader);
      lazyTsl.setCacheExpirationTime(configuration.getTslCacheExpirationTime());
      tslCertificateSource = lazyTsl;
      logger.debug("Finished loading TSL in a synchronized block");
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
