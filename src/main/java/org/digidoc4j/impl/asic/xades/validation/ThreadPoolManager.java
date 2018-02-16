/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.asic.xades.validation;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.digidoc4j.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thread pool manager
 */
public class ThreadPoolManager {

  private static final Logger logger = LoggerFactory.getLogger(ThreadPoolManager.class);
  private static ExecutorService defaultThreadExecutor;
  private Configuration configuration;

  /**
   * @param configuration configuration context
   */
  public ThreadPoolManager(Configuration configuration) {
    this.configuration = configuration;
  }

  /**
   * @param threadExecutor default thread executor
   */
  public static void setDefaultThreadExecutor(ExecutorService threadExecutor) {
    ThreadPoolManager.defaultThreadExecutor = threadExecutor;
  }

  /**
   * @return default thread executor
   */
  public static ExecutorService getDefaultThreadExecutor() {
    return ThreadPoolManager.defaultThreadExecutor;
  }

  public ExecutorService getThreadExecutor() {
    if (this.configuration.getThreadExecutor() != null) {
      return this.configuration.getThreadExecutor();
    }
    if (ThreadPoolManager.defaultThreadExecutor == null) {
      ThreadPoolManager.initializeDefaultThreadExecutor();
    }
    return ThreadPoolManager.defaultThreadExecutor;
  }

  public <T> Future<T> submit(Callable<T> task) {
    return this.getThreadExecutor().submit(task);
  }

  /*
   * RESTRICTED METHODS
   */

  private static synchronized void initializeDefaultThreadExecutor() {
    //Using double-checked locking to avoid other threads to start initializing another executor
    if (ThreadPoolManager.defaultThreadExecutor == null) {
      int numberOfProcessors = Runtime.getRuntime().availableProcessors();
      logger.debug("Initializing a new default thread pool executor with <{}> threads", numberOfProcessors);
      ThreadPoolManager.defaultThreadExecutor = Executors.newFixedThreadPool(numberOfProcessors);
    }
  }

}
