package org.digidoc4j.utils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public final class ResourceUtils {

    public static boolean isResourceAccessible(String path) {
        try {
            return ResourceUtils.class.getClassLoader().getResource(path) != null;
        } catch (RuntimeException e) {
            return false;
        }
    }

    public static boolean isFileReadable(String path) {
        try {
            Path pathToFile = Paths.get(path);
            return Files.isRegularFile(pathToFile) && Files.isReadable(pathToFile);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private ResourceUtils() {}

}
