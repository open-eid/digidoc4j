package org.digidoc4j.utils;

import org.digidoc4j.impl.asic.DataLoaderDecorator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public final class ResourceUtils {

  private static final Logger LOGGER = LoggerFactory.getLogger(ResourceUtils.class);

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

  public static Path getFullPath(String path) {
    if (path.startsWith("classpath:")) {
      path = path.substring("classpath:".length());
      try {
        URL url = DataLoaderDecorator.class.getClassLoader().getResource(path);
        if (url == null) {
          throw new IllegalArgumentException("Invalid path");
        }
        return Paths.get(url.toURI());
      } catch (URISyntaxException e) {
        throw new IllegalArgumentException("Invalid path");
      }
    } else if (path.startsWith("file:")) {
      path = path.substring("file:".length());
    }
    return Paths.get(path);
  }

  private ResourceUtils() {
  }

}
