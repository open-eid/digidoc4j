/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public final class ResourceUtils {

  private static final Logger LOGGER = LoggerFactory.getLogger(ResourceUtils.class);

  private static final String CLASSPATH_PREFIX = "classpath:";
  private static final String FILE_PREFIX = "file:";

  public static boolean isResourceAccessible(String path) {
    try {
      return ResourceUtils.class.getClassLoader().getResource(path) != null;
    } catch (RuntimeException e) {
      LOGGER.debug("Failed to acquire resource URL for path: " + path, e);
      return false;
    }
  }

  public static boolean isFileReadable(String path) {
    try {
      Path pathToFile = Paths.get(path);
      return Files.isRegularFile(pathToFile) && Files.isReadable(pathToFile);
    } catch (RuntimeException e) {
      LOGGER.debug("Failed to check if path exists as a regular file and is readable: " + path, e);
      return false;
    }
  }

  public static InputStream getResource(String path) {
    if (path.startsWith(CLASSPATH_PREFIX) || isResourceAccessible(path)) {
      if (path.startsWith(CLASSPATH_PREFIX)) {
        path = path.substring(CLASSPATH_PREFIX.length());
      }
      InputStream inputStream = ResourceUtils.class.getClassLoader().getResourceAsStream(path);
      if (inputStream == null) {
        throw new IllegalArgumentException("Classpath resource not found: " + path);
      }
      return inputStream;
    } else if (path.startsWith(FILE_PREFIX) || isFileReadable(path)) {
      if (path.startsWith(FILE_PREFIX)) {
        path = path.substring(FILE_PREFIX.length());
      }
      try {
        return new FileInputStream(path);
      } catch (FileNotFoundException e) {
        throw new IllegalArgumentException("File resource not found: " + path, e);
      }
    }
    throw new IllegalArgumentException("Resource not found: " + path);
  }

  private ResourceUtils() {
  }

}
