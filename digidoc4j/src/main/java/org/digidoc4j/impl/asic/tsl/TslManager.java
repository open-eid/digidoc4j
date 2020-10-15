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

import org.digidoc4j.Configuration;
import org.digidoc4j.TSLCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

public class TslManager implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(TslManager.class);
  private TSLCertificateSource tslCertificateSource;
  private Configuration configuration;

  public TslManager(Configuration configuration) {
    this.configuration = configuration;
  }

  public TSLCertificateSource getTsl() {
    if (this.tslCertificateSource != null) {
      logger.debug("Using TSL cached copy");
      return tslCertificateSource;
    }
    this.loadTsl();
    return this.tslCertificateSource;
  }

  public void setTsl(TSLCertificateSource certificateSource) {
    this.tslCertificateSource = certificateSource;
  }

  /**
   * Loading TSL in a single thread in a synchronized block to avoid duplicate TSL loading by multiple threads.
   */
  private synchronized void loadTsl() {
    //Using double-checked locking to avoid other threads to start loading TSL
    if (this.tslCertificateSource == null) {
      logger.debug("Loading TSL in a synchronized block");
      TslLoader tslLoader = new TslLoader(this.configuration);
      LazyTslCertificateSource lazyTsl = new LazyTslCertificateSource(tslLoader);
      lazyTsl.setCacheExpirationTime(this.configuration.getTslCacheExpirationTime());
      this.tslCertificateSource = lazyTsl;
      logger.debug("Finished loading TSL in a synchronized block");
    }
  }

}
