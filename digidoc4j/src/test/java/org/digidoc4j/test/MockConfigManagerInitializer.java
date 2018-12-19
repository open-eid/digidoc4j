/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.test;

import org.digidoc4j.Configuration;
import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class MockConfigManagerInitializer extends ConfigManagerInitializer {

  public static int configManagerCallCount = 0;

  static {
    configManagerInitialized = false;
  }

  @Override
  protected void initializeDDoc4JConfigManager(Configuration configuration) {
    super.initializeDDoc4JConfigManager(configuration);
    configManagerCallCount++;
  }

}
