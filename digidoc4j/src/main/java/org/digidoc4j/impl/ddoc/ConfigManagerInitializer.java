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
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.exceptions.TechnicalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.digidoc4j.ddoc.utils.ConfigManager;

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
      initializeDDoc4JConfigManager(configuration);
    } else {
      logger.debug("Skipping DDoc configuration manager initialization");
    }
  }

  /**
   * @param configuration configuration
   */
  public static synchronized void forceInitConfigManager(Configuration configuration) {
    logger.info("Initializing DDoc configuration manager");
    ConfigManager.init(configuration.getDDoc4JConfiguration());
    ConfigManager.addProvider();
    triggerLazilyLoadableConfigurationInitialization();
    configManagerInitialized = true;
  }

  /**
   * @return indication whether config manager is initialized
   */
  public static boolean isConfigManagerInitialized() {
    return configManagerInitialized;
  }

  protected synchronized void initializeDDoc4JConfigManager(Configuration configuration) {
    //Using double-checked locking to avoid other threads to start initialization
    if(!configManagerInitialized) {
      forceInitConfigManager(configuration);
    }
  }

  private static void triggerLazilyLoadableConfigurationInitialization() {
    ConfigManager configManager = ConfigManager.instance();
    // The following factories inside the JDigiDoc configuration are not loaded during the initialization of the
    //  ConfigManager. They are loaded and initialized lazily when they are requested from the ConfigManager for the
    //  first time. This can happen anywhere in DDoc container loading or validation logic, outside the synchronized
    //  block of the ConfigManagerInitializer.
    // Request the relevant factories from the ConfigManager instance to ensure that their loading and initialization
    //  is triggered inside the synchronized block of the ConfigManagerInitializer.
    try {
      configManager.getCanonicalizationFactory();
    } catch (DigiDocException e) {
      throw new TechnicalException("Failed to acquire DigiDoc canonicalization factory", e);
    }
    try {
      configManager.getNotaryFactory();
    } catch (DigiDocException e) {
      throw new TechnicalException("Failed to acquire DigiDoc notary factory", e);
    }
    try {
      configManager.getTslFactory();
    } catch (DigiDocException e) {
      throw new TechnicalException("Failed to acquire DigiDoc TSL factory", e);
    }
  }

}
