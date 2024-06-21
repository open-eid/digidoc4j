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
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import org.digidoc4j.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Optional;

/**
 * Manages the creation of OCSP sources during the process of signing.
 * Intended to be used internally, hence deliberately does not implement org.digidoc4j.OCSPSourceFactory interface.
 */
public class SigningOcspSourceFactory implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(SigningOcspSourceFactory.class);

  private final Configuration configuration;

  public SigningOcspSourceFactory(Configuration configuration) {
    this.configuration = configuration;
  }

  public OCSPSource create() {
    return Optional.ofNullable(configuration.getSigningOcspSourceFactory())
        .map(factory -> {
          logger.debug("Using custom OCSP source provided by the factory defined in the configuration");
          return factory.create();
        })
        .orElseGet(() -> {
          logger.debug("No custom OCSP source factory provided by the configuration, returning a default one");
          SKOnlineOCSPSource source = new CommonOCSPSource(configuration);
          DataLoader loader = new OcspDataLoaderFactory(configuration).create();
          source.setDataLoader(loader);
          return source;
        });
  }

}
