/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.test.util;

import java.io.InputStream;
import java.util.Properties;

public final class PropertiesUtil {

  public static final String VERSION = "version";

  private static final String TEST_PROPERTIES = "/test.properties";

  public static Properties getTestProperties() {
    Properties properties = new Properties();

    try (InputStream in = PropertiesUtil.class.getResourceAsStream(TEST_PROPERTIES)) {
      properties.load(in);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to load project properties", e);
    }

    return properties;
  }

}
