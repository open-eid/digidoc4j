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
 * Manages the creation of new data loaders for getting OCSP responses.
 */
public class OcspDataLoaderFactory implements DataLoaderFactory {

  private static final Logger logger = LoggerFactory.getLogger(OcspDataLoaderFactory.class);
  private Configuration configuration;
  private String userAgent;

  public OcspDataLoaderFactory(Configuration configuration, String userAgent) {
    this.configuration = configuration;
    this.userAgent = userAgent;
  }

  @Override
  public DataLoader create() {
    if (configuration.getOcspDataLoaderFactory() == null) {
      return createDataLoader();
    } else {
      logger.debug("Using custom ocsp data loader factory provided by the configuration");
      return configuration.getOcspDataLoaderFactory().create();
    }
  }

  private DataLoader createDataLoader() {
    logger.debug("Creating OCSP data loader");
    SkDataLoader dataLoader = new SkOCSPDataLoader(configuration);
    dataLoader.setUserAgent(userAgent);
    return dataLoader;
  }
}
