/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

/*
 * Thanks to Aleksandr Zhuikov (http://aleksz-programming.blogspot.com.ee/2014/02/restricting-system-resource-access-in.html)
 */
package org.digidoc4j.test;

import java.security.Permission;
import java.util.Arrays;
import java.util.Collection;

import org.apache.commons.lang3.StringUtils;
import org.junit.rules.ExternalResource;

/**
 * JUnit rule for making sure that the code under test would not write anything to the file system.
 */
public class RestrictedExternalResourceRule extends ExternalResource {

  private Collection<String> whiteList;

  public RestrictedExternalResourceRule(String... whiteList) {
    this.whiteList = Arrays.asList(whiteList);
  }

  @Override
  protected void before() throws Throwable {
    super.before();
    System.setSecurityManager(new SecurityManager() {

      @Override
      public void checkWrite(String file) {
        if (!isAllowedToWrite(file)) {
          throw new FileWritingRestrictedException();
        }
      }

      @Override
      public void checkPermission(Permission perm) {
        return;
      }
    });
  }

  @Override
  protected void after() {
    System.setSecurityManager(null); // or save and restore original
    super.after();
  }

  private boolean isAllowedToWrite(String file) {
    for (String prefix : this.whiteList) {
      if (StringUtils.startsWith(file, prefix)) {
        return true;
      }
    }
    return false;
  }

  /**
   * File writing operations happened when not allowed.
   */
  public static class FileWritingRestrictedException extends RuntimeException {
  }

}
