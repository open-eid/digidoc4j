/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.dataloader;

import java.io.File;

import org.digidoc4j.Configuration;
import org.digidoc4j.impl.bdoc.CachingDataLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.DataLoader;
import eu.europa.esig.dss.client.http.Protocol;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;

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
      logger.debug("Using custom tsl data loader factory provided by the configuration");
      return configuration.getTslDataLoaderFactory().create();
    }
  }

  protected DataLoader createDataLoader() {
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
}
