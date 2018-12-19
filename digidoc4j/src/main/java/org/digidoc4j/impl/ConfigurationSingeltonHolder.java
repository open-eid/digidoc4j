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

import org.digidoc4j.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configuration holder
 */
public class ConfigurationSingeltonHolder {

  private static final Logger logger = LoggerFactory.getLogger(ConfigurationSingeltonHolder.class);
  private static volatile Configuration configuration;

  /**
   * A thread-safe way of getting a single configuration object.
   */
  public static Configuration getInstance() {
    if (configuration == null) {
      //Using double-checked locking for ensuring that no other thread has started initializing Configuration object already
      synchronized (ConfigurationSingeltonHolder.class) {
        if (configuration == null) {
          logger.info("Creating a new configuration instance");
          configuration = new Configuration();
        }
      }
    } else {
      logger.info("Using existing configuration instance");
    }
    return configuration;
  }

  /**
   * @return configuration context
   */
  public static boolean isInitialized() {
    return ConfigurationSingeltonHolder.configuration != null;
  }

  protected static void reset() {
    configuration = null;
  }

}
