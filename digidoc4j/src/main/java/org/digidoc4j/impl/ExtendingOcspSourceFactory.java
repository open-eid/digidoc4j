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

import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import org.digidoc4j.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Optional;

/**
 * Manages the creation of OCSP sources during the process of signature extension.
 * Intended to be used internally, hence deliberately does not implement org.digidoc4j.OCSPSourceFactory interface.
 */
public class ExtendingOcspSourceFactory implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(ExtendingOcspSourceFactory.class);

  private final Configuration configuration;

  public ExtendingOcspSourceFactory(Configuration configuration) {
    this.configuration = configuration;
  }

  public OCSPSource create() {
    return Optional.ofNullable(configuration.getExtendingOcspSourceFactory())
        .map(factory -> {
          logger.debug("Using custom OCSP source provided by the factory defined in the configuration");
          return factory.create();
        })
        .orElseGet(() -> {
          logger.debug("No custom OCSP source factory provided by the configuration, returning NULL");
          return null;
        });
  }

}
