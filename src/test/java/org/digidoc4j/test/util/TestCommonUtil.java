package org.digidoc4j.test.util;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public final class TestCommonUtil {

  public static void sleepInSeconds(int seconds) {
    try {
      Thread.sleep(seconds * 1000);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

}
