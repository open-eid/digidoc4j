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

import org.digidoc4j.CertificateStatus;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class CertificateValidationException extends RuntimeException {

  public enum CertificateValidationStatus implements CertificateStatus {

    TECHNICAL, UNTRUSTED, REVOKED, UNKNOWN;

    CertificateValidationStatus() {
    }

    @Override
    public Object getStatus() {
      return this;
    }

  }

  private final CertificateStatus certificateStatus;

  protected CertificateValidationException(CertificateStatus certificateStatus) {
    super();
    this.certificateStatus = certificateStatus;
  }

  protected CertificateValidationException(CertificateStatus certificateStatus, String message) {
    super(message);
    this.certificateStatus = certificateStatus;
  }

  protected CertificateValidationException(CertificateStatus certificateStatus, String message, Throwable cause) {
    super(message, cause);
    this.certificateStatus = certificateStatus;
  }

  protected CertificateValidationException(CertificateStatus certificateStatus, Exception cause) {
    super(cause);
    this.certificateStatus = certificateStatus;
  }

  protected CertificateValidationException(String message) {
    super(message);
    this.certificateStatus = CertificateValidationStatus.TECHNICAL;
  }

  protected CertificateValidationException(Exception cause) {
    super("Unexpected error", cause);
    this.certificateStatus = CertificateValidationStatus.TECHNICAL;
  }

  /**
   * @param status status of certificate
   * @return CertificateValidationException
   */
  public static CertificateValidationException of(CertificateStatus status) {
    return new CertificateValidationException(status);
  }

  /**
   * @param status status of certificate
   * @param message error message
   * @return CertificateValidationException
   */
  public static CertificateValidationException of(CertificateStatus status, String message) {
    return new CertificateValidationException(status, message);
  }

  /**
   * @param status status of certificate
   * @param message error message
   * @param cause cause of error
   * @return CertificateValidationException
   */
  public static CertificateValidationException of(CertificateStatus status, String message, Throwable cause) {
    return new CertificateValidationException(status, message, cause);
  }

  /**
   * @param status status of certificate
   * @param  cause cause of error
   * @return CertificateValidationException
   */
  public static CertificateValidationException of(CertificateStatus status, Exception cause) {
    return new CertificateValidationException(status, cause);
  }

  /**
   * @param message error message
   * @return CertificateValidationException
   */
  public static CertificateValidationException of(String message) {
    return new CertificateValidationException(message);
  }

  /**
   * @param cause cause of exception
   * @return CertificateValidationException
   */
  public static CertificateValidationException of(Exception cause) {
    return new CertificateValidationException(cause);
  }

  /*
   * ACCESSORS
   */

  public CertificateStatus getCertificateStatus() {
    return certificateStatus;
  }

}
