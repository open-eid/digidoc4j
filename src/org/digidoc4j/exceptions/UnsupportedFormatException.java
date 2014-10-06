package org.digidoc4j.exceptions;

/**
 * Exception what describes unsupported container formats
 */
public class UnsupportedFormatException extends DigiDoc4JException {

  /**
   * Constructs new exception
   *
   * @param type message to to be shown
   */
  public UnsupportedFormatException(String type) {
    super("Unsupported format: " + type);
  }
}
