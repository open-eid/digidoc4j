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

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.impl.asic.xades.validation.ThreadPoolManager;
import org.junit.Assert;
import org.junit.Test;

public class ThreadPoolManagerTest extends AbstractTest {

  private ThreadPoolManager manager;

  @Test
  public void getDefaultThreadExecutor() throws Exception {
    Assert.assertNotNull(this.manager.getThreadExecutor());
  }

  @Test
  public void setDefaultThreadExecutor() throws Exception {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    ThreadPoolManager.setDefaultThreadExecutor(executor);
    Assert.assertSame(executor, this.manager.getThreadExecutor());
  }

  @Test
  public void setThreadExecutorInConfiguration() throws Exception {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    this.configuration.setThreadExecutor(executor);
    Assert.assertSame(executor, this.manager.getThreadExecutor());
  }

  @Test
  public void submitTaskToThreadExecutorSetInConfiguration() throws Exception {
    CustomExecutorService executor = new CustomExecutorService();
    this.configuration.setThreadExecutor(executor);
    Callable callable = new Callable<Object>() {

      @Override
      public Object call() throws Exception {
        return null;
      }

    };
    this.manager.submit(callable);
    Assert.assertSame(callable, executor.getTasks().get(0));
  }

  @Test
  public void validateContainerWithCustomThreadExecutor() throws Exception {
    CustomExecutorService executor = new CustomExecutorService();
    this.configuration.setThreadExecutor(executor);
    SignatureValidationResult result = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/invalid-containers/two_signatures.bdoc"), this.configuration).validate();
    Assert.assertFalse(result.isValid());
    Assert.assertEquals(2, executor.getTasks().size());  //Two signatures must be validated within a thread pool
  }

  /*
   * PROTECTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.manager = new ThreadPoolManager(this.configuration);
  }

  private static class CustomExecutorService extends ThreadPoolExecutor {

    private List<Callable> tasks = new ArrayList<>();

    public CustomExecutorService() {
      super(1, 1, 1, TimeUnit.SECONDS, new ArrayBlockingQueue(10));
    }

    @Override
    public <T> Future<T> submit(Callable<T> task) {
      this.tasks.add(task);
      return super.submit(task);
    }

    public List<Callable> getTasks() {
      return tasks;
    }

  }

}
