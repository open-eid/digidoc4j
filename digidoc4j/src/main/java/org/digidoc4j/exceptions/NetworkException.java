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

import org.digidoc4j.ServiceType;

public class NetworkException extends TechnicalException {

  private final String serviceUrl;
  private final ServiceType serviceType;

  public NetworkException(String message, String serviceUrl, ServiceType serviceType) {
    super(message);
    this.serviceUrl = serviceUrl;
    this.serviceType = serviceType;
  }

  public NetworkException(String message, String serviceUrl, ServiceType serviceType, Throwable cause) {
    super(message, cause);
    this.serviceUrl = serviceUrl;
    this.serviceType = serviceType;
  }

  public String getServiceUrl() {
    return serviceUrl;
  }

  public ServiceType getServiceType() {
    return serviceType;
  }
}
