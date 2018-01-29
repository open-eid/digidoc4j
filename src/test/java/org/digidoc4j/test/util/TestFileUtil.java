package org.digidoc4j.test.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class TestFileUtil {

  public static FileTime creationTime(Path filePath) {
    try {
      return (FileTime) Files.getAttribute(filePath, "basic:creationTime");
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

}
