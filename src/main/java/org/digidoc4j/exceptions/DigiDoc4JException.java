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

import org.apache.commons.lang3.StringUtils;

/**
 * Generic exception for DigiDoc4J
 */
public class DigiDoc4JException extends RuntimeException {

  int errorCode = 0;
  private String signatureId = "";

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
   * @param cause cause of exception
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
   * Constructs a new runtime exception with the specified detail message, signature ID and
   * cause.  <p>Note that the detail message associated with
   * {@code cause} is <i>not</i> automatically incorporated in
   * this runtime exception's detail message.
   *
   * @param message the detail message (which is saved for later retrieval
   *                by the {@link #getMessage()} method).
   * @param signatureId  - Signature ID
   */
  public DigiDoc4JException(String message, String signatureId) {
    super(message);
    this.signatureId = signatureId;
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

  public DigiDoc4JException() {
  }

  /**
   * Get the error code of the exception
   *
   * @return error code
   */
  public int getErrorCode() {
    return errorCode;
  }


  /**
   * Get the Signature Id of the exception
   *
   * @return id of signature
   */
  public String getSignatureId() {
    return signatureId;
  }

  /**
   * Set the Signature Id of the exception
   *
   * @param signatureId id of signature
   */
  public void setSignatureId(String signatureId) {
    this.signatureId = signatureId;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    if (StringUtils.isNotBlank(this.signatureId))  {
      sb.append("(Signature ID: ").append(this.signatureId).append(") - ");
    }
    if (this.errorCode != 0) {
      sb.append("ERROR: ").append(this.errorCode).append(" - ");
    }
    sb.append(this.getMessage());
    return sb.toString();
  }

}
