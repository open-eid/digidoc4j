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
    if (path.startsWith("classpath:")) {
      path = path.substring("classpath:".length());
      InputStream inputStream = ResourceUtils.class.getClassLoader().getResourceAsStream(path);
      if (inputStream == null) {
        throw new IllegalArgumentException("Resource not found: " + path);
      }
      return inputStream;
    } else if (path.startsWith("file:")) {
      path = path.substring("file:".length());
    }
    try {
      return new FileInputStream(path);
    } catch (FileNotFoundException e) {
      throw new IllegalArgumentException("Resource not found: " + path);
    }
  }

  private ResourceUtils() {
  }

}
