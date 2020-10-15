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
import org.digidoc4j.ExternalConnectionType;
import org.digidoc4j.ServiceType;
import org.digidoc4j.impl.asic.DataLoaderDecorator;

public class SkTimestampDataLoader extends SkDataLoader {

  protected static final String TIMESTAMP_QUERY_CONTENT_TYPE = "application/timestamp-query";

  public SkTimestampDataLoader(Configuration configuration) {
    DataLoaderDecorator.decorateWithProxySettingsFor(ExternalConnectionType.TSP, this, configuration);
    DataLoaderDecorator.decorateWithSslSettingsFor(ExternalConnectionType.TSP, this, configuration);
    contentType = TIMESTAMP_QUERY_CONTENT_TYPE;
  }

  @Override
  protected ServiceType getServiceType() {
    return ServiceType.TSP;
  }
}
