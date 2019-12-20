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

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataLoaderFactory;
import org.digidoc4j.ExternalConnectionType;
import org.digidoc4j.impl.asic.DataLoaderDecorator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages the creation of data loaders for downloading certificates from the Trust Store (TSL).
 */
public class TslDataLoaderFactory implements DataLoaderFactory {

  private static final Logger logger = LoggerFactory.getLogger(TslDataLoaderFactory.class);
  private Configuration configuration;
  private File fileCacheDirectory;

  public TslDataLoaderFactory(Configuration configuration, File fileCacheDirectory) {
    this.configuration = configuration;
    this.fileCacheDirectory = fileCacheDirectory;
  }

  @Override
  public DataLoader create() {
    if (configuration.getTslDataLoaderFactory() == null) {
      return createDataLoader();
    } else {
      logger.debug("Using custom TSL data loader factory provided by the configuration");
      return configuration.getTslDataLoaderFactory().create();
    }
  }

  private DataLoader createDataLoader() {
    CommonsDataLoader commonsDataLoader = new CommonsDataLoader();
    if (Protocol.isHttpUrl(this.configuration.getTslLocation())) {
      DataLoaderDecorator.decorateWithProxySettingsFor(ExternalConnectionType.TSL, commonsDataLoader, configuration);
      DataLoaderDecorator.decorateWithSslSettingsFor(ExternalConnectionType.TSL, commonsDataLoader, configuration);
      commonsDataLoader.setTimeoutConnection(this.configuration.getConnectionTimeout());
      commonsDataLoader.setTimeoutSocket(this.configuration.getSocketTimeout());
      FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader(commonsDataLoader);
      fileCacheDataLoader.setCacheExpirationTime(this.configuration.getTslCacheExpirationTime());
      fileCacheDataLoader.setFileCacheDirectory(this.fileCacheDirectory);
      logger.debug("Using file cache directory for storing TSL: {}", this.fileCacheDirectory);
      return fileCacheDataLoader;
    } else {
      return commonsDataLoader;
    }
  }
}
