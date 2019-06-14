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
import org.digidoc4j.ServiceType;

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
  private ServiceType serviceType;
  private String serviceUrl;

  private CertificateValidationException(CertificateStatus certificateStatus, String message, Throwable cause) {
    super(message, cause);
    this.certificateStatus = certificateStatus;
  }

  /**
   * @param status status of certificate
   * @param message error message
   * @return CertificateValidationException
   */
  public static CertificateValidationException of(CertificateStatus status, String message) {
    return new CertificateValidationException(status, message, null);
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

  /*
   * ACCESSORS
   */

  public void setServiceType(ServiceType serviceType) {
    this.serviceType = serviceType;
  }

  public void setServiceUrl(String serviceUrl) {
    this.serviceUrl = serviceUrl;
  }

  public CertificateStatus getCertificateStatus() {
    return certificateStatus;
  }

  public ServiceType getServiceType() {
    return serviceType;
  }

  public String getServiceUrl() {
    return serviceUrl;
  }
}
