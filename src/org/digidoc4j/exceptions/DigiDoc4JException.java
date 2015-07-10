/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.exceptions;

/**
 * Generic exception for DigiDoc4J
 */
public class DigiDoc4JException extends RuntimeException {

  int errorCode = 0;

  /**
   * Constructs a new runtime exception with the specified detail message and
   * cause.  <p>Note that the detail message associated with
   * {@code cause} is <i>not</i> automatically incorporated in
   * this runtime exception's detail message.
   *
   * @param error   - error code
   * @param message the detail message (which is saved for later retrieval
   *                by the {@link #getMessage()} method).
   */
  public DigiDoc4JException(int error, String message) {
    super(message);
    errorCode = error;
  }
  
  /**
   * Constructs a new runtime exception with the specified detail message and
   * cause.  <p>Note that the detail message associated with
   * {@code cause} is <i>not</i> automatically incorporated in
   * this runtime exception's detail message.
   *
   * @param message the detail message (which is saved for later retrieval
   *                by the {@link #getMessage()} method).
   */
  public DigiDoc4JException(String message, Throwable cause) {
    super(message, cause);
  }

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

  /**
   * Creates new exception based on another exception
   *
   * @param e parent exception
   */
  public DigiDoc4JException(Throwable e) {
    super(e);
  }

  /**
   * Creates new exception based on another exception
   *
   * @param e parent exception
   */
  public DigiDoc4JException(Exception e) {
    super(e);
  }

  /**
   * Get the error code of the exception
   *
   * @return error code
   */
  public int getErrorCode() {
    return errorCode;
  }

  @Override
  public String toString() {
    StringBuilder msg = new StringBuilder();
    if (errorCode != 0) msg.append("ERROR: ").append(errorCode).append(" - ");
    msg.append(getMessage());
    return msg.toString();
  }
}
