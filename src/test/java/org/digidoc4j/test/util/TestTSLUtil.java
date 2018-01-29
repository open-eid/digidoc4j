package org.digidoc4j.test.util;

import java.io.File;

import org.digidoc4j.impl.asic.tsl.TslLoader;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class TestTSLUtil {

  public static void deleteCache() {
    TslLoader.invalidateCache();
  }

  public static long getCacheLastModified() {
    return TestTSLUtil.getCachedFile(TslLoader.fileCacheDirectory).lastModified();
  }

  private static File getCachedFile(File cacheDirectory) { // TODO refactor
    File cachedFile = null;
    if (cacheDirectory.exists()) {
      File[] files = cacheDirectory.listFiles();
      if (files != null && files.length > 0) {
        cachedFile = files[0];
        long modificationTime = cachedFile.lastModified();
        for (File file : files) {
          if (file.lastModified() > modificationTime) {
            cachedFile = file;
          }
        }
      }
    }
    return cachedFile;
  }

}
