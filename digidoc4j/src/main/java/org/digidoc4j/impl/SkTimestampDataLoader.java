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

import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import org.digidoc4j.Configuration;
import org.digidoc4j.ServiceType;

public class SkTimestampDataLoader extends SkDataLoader {

  public SkTimestampDataLoader(Configuration configuration) {
    super(configuration);
    contentType = TimestampDataLoader.TIMESTAMP_QUERY_CONTENT_TYPE;
  }

  @Override
  protected ServiceType getServiceType() {
    return ServiceType.TSP;
  }
}
