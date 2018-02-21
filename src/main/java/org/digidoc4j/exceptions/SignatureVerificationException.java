package org.digidoc4j.exceptions;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public class SignatureVerificationException extends DigiDoc4JException {

  /**
   * @param message error message
   */
  public SignatureVerificationException(String message) {
    super(message);
  }

  /**
   * @param message error message
   * @param cause cause
   */
  public SignatureVerificationException(String message, Exception cause) {
    super(message, cause);
  }

}
