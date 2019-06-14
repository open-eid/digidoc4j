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

public class ConnectionTimedOutException extends NetworkException {

  public ConnectionTimedOutException(String serviceUrl, ServiceType serviceType) {
    super(String.format("Connection to %s service <%s> timed out", serviceType, serviceUrl), serviceUrl, serviceType);
  }
}
