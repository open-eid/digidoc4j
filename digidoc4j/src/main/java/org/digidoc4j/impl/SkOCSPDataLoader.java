/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import org.digidoc4j.Configuration;
import org.digidoc4j.ServiceType;

public class SkOCSPDataLoader extends SkDataLoader {

  private boolean isAiaOcsp = false;

  public SkOCSPDataLoader(Configuration configuration) {
    super(configuration);
    contentType = OCSPDataLoader.OCSP_CONTENT_TYPE;
  }

  public void setAsAiaOcsp(boolean isAiaOcsp) {
    this.isAiaOcsp = isAiaOcsp;
  }

  @Override
  protected ServiceType getServiceType() {
    return isAiaOcsp ? ServiceType.AIA_OCSP : ServiceType.OCSP;
  }
}
