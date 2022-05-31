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

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.digidoc4j.Configuration;
import org.digidoc4j.DSSFileLoaderFactory;
import org.digidoc4j.ExternalConnectionType;
import org.digidoc4j.impl.asic.DataLoaderDecorator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

/**
 * Manages the creation of file loaders for downloading certificates from the Trust Store (TSL).
 */
public class TslFileLoaderFactory implements DSSFileLoaderFactory {

  private static final Logger logger = LoggerFactory.getLogger(TslFileLoaderFactory.class);

  private final Configuration configuration;
  private final File fileCacheDirectory;

  public TslFileLoaderFactory(Configuration configuration, File fileCacheDirectory) {
    this.configuration = configuration;
    this.fileCacheDirectory = fileCacheDirectory;
  }

  @Override
  public DSSFileLoader create() {
    if (configuration.getTslFileLoaderFactory() != null) {
      logger.debug("Using custom TSL file loader factory provided by the configuration");
      return configuration.getTslFileLoaderFactory().create();
    } else if (configuration.getTslDataLoaderFactory() != null) {
      DataLoader customDataLoader = configuration.getTslDataLoaderFactory().create();
      if (customDataLoader instanceof DSSFileLoader) {
        logger.debug("Using custom TSL data loader factory provided by the configuration");
        return (DSSFileLoader) customDataLoader;
      } else {
        logger.debug("Using custom TSL data loader factory with default file cache");
        return wrapIntoFileCacheDataLoader(customDataLoader);
      }
    } else {
      logger.debug("Using default TSL file loader factory");
      return createDefaultFileLoader();
    }
  }

  private DSSFileLoader createDefaultFileLoader() {
    CommonsDataLoader commonsDataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettingsFor(ExternalConnectionType.TSL, commonsDataLoader, configuration);
    DataLoaderDecorator.decorateWithSslSettingsFor(ExternalConnectionType.TSL, commonsDataLoader, configuration);
    commonsDataLoader.setTimeoutConnection(this.configuration.getConnectionTimeout());
    commonsDataLoader.setTimeoutConnectionRequest(this.configuration.getConnectionTimeout());
    commonsDataLoader.setTimeoutSocket(this.configuration.getSocketTimeout());
    return wrapIntoFileCacheDataLoader(commonsDataLoader);
  }

  private DSSFileLoader wrapIntoFileCacheDataLoader(DataLoader dataLoader) {
    FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader(dataLoader);
    fileCacheDataLoader.setCacheExpirationTime(this.configuration.getTslCacheExpirationTime());
    logger.debug("Using file cache directory for storing TSL: {}", this.fileCacheDirectory);
    fileCacheDataLoader.setFileCacheDirectory(this.fileCacheDirectory);
    return fileCacheDataLoader;
  }

}
