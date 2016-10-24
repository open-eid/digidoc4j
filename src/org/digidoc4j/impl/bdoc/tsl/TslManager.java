/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.tsl;

import java.io.Serializable;

import org.digidoc4j.Configuration;
import org.digidoc4j.TSLCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TslManager implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(TslManager.class);
  private TSLCertificateSource tslCertificateSource;
  private Configuration configuration;

  public TslManager(Configuration configuration) {
    this.configuration = configuration;
  }

  public TSLCertificateSource getTsl() {
    if (tslCertificateSource != null) {
      logger.debug("Using TSL cached copy");
      return tslCertificateSource;
    }
    loadTsl();
    return tslCertificateSource;
  }

  public void setTsl(TSLCertificateSource certificateSource) {
    this.tslCertificateSource = certificateSource;
  }

  /**
   * Loading TSL in a single thread in a synchronized block to avoid duplicate TSL loading by multiple threads.
   */
  private synchronized void loadTsl() {
    //Using double-checked locking to avoid other threads to start loading TSL
    if(tslCertificateSource == null) {
      logger.debug("Loading TSL in a synchronized block");
      TslLoader tslLoader = new TslLoader(configuration);
      tslLoader.setCheckSignature(configuration.shouldValidateTslSignature());
      LazyTslCertificateSource lazyTsl = new LazyTslCertificateSource(tslLoader);
      lazyTsl.setCacheExpirationTime(configuration.getTslCacheExpirationTime());
      tslCertificateSource = lazyTsl;
      logger.debug("Finished loading TSL in a synchronized block");
    }
  }

}
