package org.digidoc4j.test.retry;

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rule to provide option to run failed test given times or until it passes.
 * Can be used for flaky tests that sometimes fail for known but un-fixable reason.
 */
public class RetryRule implements TestRule {

  private AtomicInteger retryCount;

  public RetryRule(int retries) {
    super();
    this.retryCount = new AtomicInteger(retries);
  }

  @Override
  public Statement apply(final Statement base, final Description description) {
    return new Statement() {
      @Override
      public void evaluate() throws Throwable {
        Throwable caughtThrowable = null;

        while (retryCount.getAndDecrement() > 0) {
          try {
            base.evaluate();
            return;
          } catch (Throwable cause) {
            if (retryCount.get() > 0 && description.getAnnotation(Retry.class) != null) {
              caughtThrowable = cause;
              System.err.println(description.getDisplayName() + ": Flaky test failed, " + retryCount.toString() + " retries remain");
            } else {
              System.err.println("Flaky test failed for maximum allowed times (" + retryCount.get() + ")");
              throw caughtThrowable;
            }
          }
        }
      }
    };
  }
}