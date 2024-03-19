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

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;

/**
 * A helper class for determining the current JRE version for testing purposes.
 * TODO (DD4J-993): Consider removing this class when DD4J unit tests are migrated to JUnit5.
 *  JUnit5 has annotations for conditional test execution based on JRE versions.
 * TODO: Consider removing this class when the minimum supported version of DD4J is raised to Java 9+.
 *  In Java 9+, {@code java.lang.Runtime.version().major()} can be called directly.
 */
public final class JreVersionHelper {

  private static final Logger LOGGER = LoggerFactory.getLogger(JreVersionHelper.class);

  public static Integer getCurrentMajorVersionIfAvailable() {
    String versionString = System.getProperty("java.version");
    if (StringUtils.startsWith(versionString, "1.8")) {
      return 8;
    }

    try {
      // java.lang.Runtime.version() is a static method available on Java 9+
      // that returns an instance of java.lang.Runtime.Version which has the
      // following method: public int major()
      Method versionMethod = Runtime.class.getMethod("version");
      Object version = makeAccessible(versionMethod).invoke(null);
      Method majorMethod = version.getClass().getMethod("major");
      return (int) makeAccessible(majorMethod).invoke(version);
    } catch (Exception ex) {
      LOGGER.warn("Failed to determine the current JRE version via java.lang.Runtime.Version.", ex);
    }

    if (StringUtils.isBlank(versionString)) {
      LOGGER.warn("JVM system property 'java.version' is undefined. Unable to determine the current JRE version.");
    }

    return null;
  }

  private static Method makeAccessible(Method method) {
    if (!method.isAccessible()) {
      method.setAccessible(true);
    }
    return method;
  }

}
