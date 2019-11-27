package org.digidoc4j.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private ResourceUtils() {}

}
