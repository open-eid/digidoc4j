/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.ddoc;

import java.io.Serializable;

import org.digidoc4j.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ee.sk.utils.ConfigManager;

/**
 * Configuration manager initializer
 */
public class ConfigManagerInitializer implements Serializable{

  private static final Logger logger = LoggerFactory.getLogger(ConfigManagerInitializer.class);
  protected static boolean configManagerInitialized = false;

  /**
   * @param configuration configuration
   */
  public void initConfigManager(Configuration configuration) {
    if(!configManagerInitialized) {
      initializeJDigidocConfigManager(configuration);
    } else {
      logger.debug("Skipping DDoc configuration manager initialization");
    }
  }

  /**
   * @param configuration configuration
   */
  public static synchronized void forceInitConfigManager(Configuration configuration) {
    logger.info("Initializing DDoc configuration manager");
    ConfigManager.init(configuration.getJDigiDocConfiguration());
    ConfigManager.addProvider();
    configManagerInitialized = true;
  }

  /**
   * @return indication whether config manager is initialized
   */
  public static boolean isConfigManagerInitialized() {
    return configManagerInitialized;
  }

  protected synchronized void initializeJDigidocConfigManager(Configuration configuration) {
    //Using double-checked locking to avoid other threads to start initialization
    if(!configManagerInitialized) {
      forceInitConfigManager(configuration);
    }
  }

}
