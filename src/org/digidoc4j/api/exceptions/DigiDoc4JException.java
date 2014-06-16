package org.digidoc4j.api.exceptions;

/**
 * Generic exception for DigiDoc4J
 */
public class DigiDoc4JException extends RuntimeException {

  /**
   * Constructs a new runtime exception with the specified detail message and
   * cause.  <p>Note that the detail message associated with
   * {@code cause} is <i>not</i> automatically incorporated in
   * this runtime exception's detail message.
   *
   * @param message the detail message (which is saved for later retrieval
   *                by the {@link #getMessage()} method).
   */
  public DigiDoc4JException(String message) {
    super(message);
  }

  public DigiDoc4JException(Exception e) {
    super(e.getMessage(), e.getCause());
  }
}
