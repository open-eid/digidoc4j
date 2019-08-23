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

public class ServiceUnreachableException extends NetworkException {

  public ServiceUnreachableException(String serviceUrl, ServiceType serviceType) {
    super(String.format("Failed to connect to %s service <%s>. Service is down or URL is invalid.", serviceType, serviceUrl), serviceUrl, serviceType);
  }
}
