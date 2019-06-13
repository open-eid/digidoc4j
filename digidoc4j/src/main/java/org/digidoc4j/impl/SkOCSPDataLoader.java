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

import eu.europa.esig.dss.client.http.commons.OCSPDataLoader;
import org.digidoc4j.Configuration;

public class SkOCSPDataLoader extends SkDataLoader {

  public static final String SERVICE_TYPE = "OCSP";

  public SkOCSPDataLoader(Configuration configuration) {
    super(configuration);
    contentType = OCSPDataLoader.OCSP_CONTENT_TYPE;
  }

  @Override
  protected void logAction(String url) {
    LOGGER.debug("Getting OCSP response from <{}>", url);
  }

  @Override
  protected String getServiceType() {
    return SERVICE_TYPE;
  }

}
