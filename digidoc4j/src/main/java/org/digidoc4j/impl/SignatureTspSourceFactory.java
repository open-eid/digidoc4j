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

import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.TSPSourceFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.Optional;

/**
 * Manages the creation of TSP sources for signature timestamps.
 */
public class SignatureTspSourceFactory {

  private static final Logger logger = LoggerFactory.getLogger(SignatureTspSourceFactory.class);

  private final Configuration configuration;
  private final String preferredCountry;

  public SignatureTspSourceFactory(Configuration configuration) {
    this(configuration, null);
  }

  public SignatureTspSourceFactory(Configuration configuration, String preferredCountry) {
    this.configuration = Objects.requireNonNull(configuration);
    this.preferredCountry = preferredCountry;
  }

  public TSPSource create() {
    TSPSourceFactory factory = configuration.getSignatureTspSourceFactory();

    if (factory != null) {
      logger.debug("Using custom signature TSP source factory provided by the configuration");
      return factory.create();
    }

    String tspServiceUrl = Optional
            .ofNullable(preferredCountry)
            .map(configuration::getTspSourceByCountry)
            .filter(StringUtils::isNotBlank)
            .orElseGet(configuration::getTspSource);

    logger.debug("Creating default signature TSP source using TSP service URL: {}", tspServiceUrl);
    return new OnlineTSPSource(
            tspServiceUrl,
            new TspDataLoaderFactory(configuration).create()
    );
  }

}
