package org.digidoc4j;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.test.Refactored;
import org.junit.After;
import org.junit.Rule;
import org.junit.experimental.categories.Category;
import org.junit.internal.AssumptionViolatedException;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

@Category(Refactored.class)
public abstract class AbstractTest1 {

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @Rule
  public TestWatcher watcher = new TestWatcher() {

    private final Logger log = LoggerFactory.getLogger(Refactored.class);

    @Override
    protected void starting(Description description) {
      String starting = String.format("Starting --> %s.%s", description.getClassName(), description.getMethodName());
      this.log.info(StringUtils.rightPad("-", starting.length(), '-'));
      this.log.info(starting);
      this.log.info(StringUtils.rightPad("-", starting.length(), '-'));
    }

    @Override
    protected void succeeded(Description description) {
      this.log.info("Finished --> {}.{}", description.getClassName(), description.getMethodName());
    }

    @Override
    protected void failed(Throwable e, Description description) {
      this.log.error(String.format("Finished --> %s.%s", description.getClassName(), description.getMethodName()), e);
    }

    @Override
    protected void skipped(AssumptionViolatedException e, Description description) {
      String skipped = String.format("Skipped --> %s.%s", description.getClassName(), description.getMethodName());
      this.log.debug(StringUtils.rightPad("-", skipped.length(), '-'));
      this.log.debug(skipped);
      this.log.debug(StringUtils.rightPad("-", skipped.length(), '-'));
    }

  };

  @After
  public void tearDown() { // TODO
    System.clearProperty("digidoc4j.mode");
  }

}
