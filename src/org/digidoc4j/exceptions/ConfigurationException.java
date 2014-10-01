package org.digidoc4j.exceptions;

/**
 * Exeptions related to digidoc4J configuration settings
 */
public class ConfigurationException extends DigiDoc4JException {
  /**
   * Create a configuration exception with give message
   *
   * @param message Message for the exception
   */
  public ConfigurationException(String message) {
    super(message);
  }

  /**
   * Create a configuration exception using an exception object
   *
   * @param e Exception used as source for this exception
   */
  public ConfigurationException(Exception e) {
    super(e);
  }
}
