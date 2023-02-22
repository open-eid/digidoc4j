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
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import org.digidoc4j.AIASourceFactory;
import org.digidoc4j.Configuration;
import org.digidoc4j.Constant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages the creation of AIA sources.
 */
public class AiaSourceFactory implements AIASourceFactory {

  private static final Logger logger = LoggerFactory.getLogger(AiaSourceFactory.class);

  private final Configuration configuration;

  public AiaSourceFactory(Configuration configuration) {
    this.configuration = configuration;
  }

  @Override
  public AIASource create() {
    if (configuration.getAiaSourceFactory() != null) {
      logger.debug("Using custom AIA source factory provided by the configuration");
      return configuration.getAiaSourceFactory().create();
    } else if (configuration.getAiaDataLoaderFactory() != null) {
      logger.debug("Creating DefaultAIASource using custom AIA data loader factory provided by configuration");
      return wrapIntoDefaultAIASource(configuration.getAiaDataLoaderFactory().create());
    } else {
      logger.debug("Creating DefaultAIASource with default AIA data loader");
      return wrapIntoDefaultAIASource(createDefaultAiaDataLoader());
    }
  }

  private static AIASource wrapIntoDefaultAIASource(DataLoader dataLoader) {
    return new DefaultAIASource(dataLoader);
  }

  private DataLoader createDefaultAiaDataLoader() {
    return AiaDataLoaderFactory.createDefaultAiaDataLoader(configuration, Constant.USER_AGENT_STRING);
  }

}
