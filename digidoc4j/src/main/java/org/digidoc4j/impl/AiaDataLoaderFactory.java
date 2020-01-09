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

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataLoaderFactory;
import org.digidoc4j.ExternalConnectionType;
import org.digidoc4j.impl.asic.DataLoaderDecorator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages the creation of data loaders for accessing AIA certificate sources.
 */
public class AiaDataLoaderFactory implements DataLoaderFactory {

  private static final Logger logger = LoggerFactory.getLogger(AiaDataLoaderFactory.class);
  private Configuration configuration;

  public AiaDataLoaderFactory(Configuration configuration) {
    this.configuration = configuration;
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
    CommonsDataLoader dataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettingsFor(ExternalConnectionType.AIA, dataLoader, configuration);
    DataLoaderDecorator.decorateWithSslSettingsFor(ExternalConnectionType.AIA, dataLoader, configuration);
    return dataLoader;
  }

}
