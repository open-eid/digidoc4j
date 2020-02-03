/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataLoaderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages the creation of data loaders for accessing AIA certificate sources.
 */
public class AiaDataLoaderFactory implements DataLoaderFactory {

  private static final Logger logger = LoggerFactory.getLogger(AiaDataLoaderFactory.class);
  private static final int MAX_REDIRECTS_TO_FOLLOW = 5;

  private Configuration configuration;
  private String userAgent;

  public AiaDataLoaderFactory(Configuration configuration, String userAgent) {
    this.configuration = configuration;
    this.userAgent = userAgent;
  }

  @Override
  public DataLoader create() {
    if (configuration.getAiaDataLoaderFactory() == null) {
      return createDataLoader();
    } else {
      logger.debug("Using custom AIA data loader factory provided by the configuration");
      return configuration.getAiaDataLoaderFactory().create();
    }
  }

  private DataLoader createDataLoader() {
    logger.debug("Creating AIA data loader");
    SimpleHttpGetDataLoader dataLoader = new SimpleHttpGetDataLoader();
    dataLoader.setConnectTimeout(configuration.getConnectionTimeout());
    dataLoader.setReadTimeout(configuration.getSocketTimeout());
    dataLoader.setFollowRedirects(MAX_REDIRECTS_TO_FOLLOW);
    dataLoader.setUserAgent(userAgent);
    return dataLoader;
  }

}
