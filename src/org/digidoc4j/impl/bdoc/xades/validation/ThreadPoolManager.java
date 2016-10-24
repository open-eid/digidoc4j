/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.xades.validation;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.digidoc4j.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ThreadPoolManager {

  private final static Logger logger = LoggerFactory.getLogger(ThreadPoolManager.class);
  private static ExecutorService defaultThreadExecutor;
  private Configuration configuration;

  public ThreadPoolManager(Configuration configuration) {
    this.configuration = configuration;
  }

  public static void setDefaultThreadExecutor(ExecutorService threadExecutor) {
    ThreadPoolManager.defaultThreadExecutor = threadExecutor;
  }

  public ExecutorService getThreadExecutor() {
    if (configuration.getThreadExecutor() != null) {
      return configuration.getThreadExecutor();
    }
    if (defaultThreadExecutor == null) {
      initializeDefaultThreadExecutor();
    }
    return defaultThreadExecutor;
  }

  private static synchronized void initializeDefaultThreadExecutor() {
    //Using double-checked locking to avoid other threads to start initializing another executor
    if (defaultThreadExecutor == null) {
      int numberOfProcessors = Runtime.getRuntime().availableProcessors();
      logger.debug("Initializing a new default thread pool executor with " + numberOfProcessors + " threads");
      defaultThreadExecutor = Executors.newFixedThreadPool(numberOfProcessors);
    }
  }

  public <T> Future<T> submit(Callable<T> task) {
    return getThreadExecutor().submit(task);
  }
}
