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

import org.junit.jupiter.api.extension.BeforeTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public class LoggingTestWatcher implements TestWatcher, BeforeTestExecutionCallback {

  private static final Logger LOGGER = LoggerFactory.getLogger(LoggingTestWatcher.class);
  private long startTimestamp;

  @Override
  public void testDisabled(ExtensionContext context, Optional<String> reason) {
    LOGGER.debug("Skipped <{}>", context.getDisplayName());
  }

  @Override
  public void testSuccessful(ExtensionContext context) {
    long endTimestamp = System.currentTimeMillis();
    LOGGER.info("Finished <{}> - took <{}> ms", context.getDisplayName(), endTimestamp - startTimestamp);
  }

  @Override
  public void testAborted(ExtensionContext context, Throwable cause) {
    LOGGER.warn("Skipped <{}>", context.getDisplayName());
  }

  @Override
  public void testFailed(ExtensionContext context, Throwable cause) {
    long endTimestamp = System.currentTimeMillis();
    LOGGER.error("Finished <{}> - failed - took <{}> ms", context.getDisplayName(), endTimestamp -startTimestamp, cause);
  }

  @Override
  public void beforeTestExecution(ExtensionContext context) {
    LOGGER.info("------------------------------------------");
    LOGGER.info("Starting <{}>", context.getDisplayName());
    LOGGER.info("------------------------------------------");
    this.startTimestamp = System.currentTimeMillis();
  }
}
