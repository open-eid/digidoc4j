/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic;

import org.digidoc4j.Configuration;

import eu.europa.esig.dss.client.http.commons.FileCacheDataLoader;

/**
 * Cache data loader
 */
public class CachingDataLoader extends FileCacheDataLoader {

  /**
   * @param configuration configuration
   */
  public CachingDataLoader(Configuration configuration) {
    DataLoaderDecorator.decorateWithProxySettings(this, configuration);
    DataLoaderDecorator.decorateWithSslSettings(this, configuration);
  }

}
