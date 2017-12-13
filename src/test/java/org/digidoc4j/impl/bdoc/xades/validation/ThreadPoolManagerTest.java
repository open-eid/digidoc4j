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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.impl.asic.xades.validation.ThreadPoolManager;
import org.junit.Before;
import org.junit.Test;

public class ThreadPoolManagerTest {

  private Configuration configuration;
  private ThreadPoolManager manager;

  @Before
  public void setUp() throws Exception {
    configuration = new Configuration(Configuration.Mode.TEST);
    manager = new ThreadPoolManager(configuration);
  }

  @Test
  public void getDefaultThreadExecutor() throws Exception {
    assertNotNull(manager.getThreadExecutor());
  }

  @Test
  public void setDefaultThreadExecutor() throws Exception {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    ThreadPoolManager.setDefaultThreadExecutor(executor);
    assertSame(executor, manager.getThreadExecutor());
  }

  @Test
  public void setThreadExecutorInConfiguration() throws Exception {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    configuration.setThreadExecutor(executor);
    assertSame(executor, manager.getThreadExecutor());
  }

  @Test
  public void submitTaskToThreadExecutorSetInConfiguration() throws Exception {
    ExecutorServiceSpy executor = new ExecutorServiceSpy();
    configuration.setThreadExecutor(executor);
    DummyTask task = new DummyTask();
    manager.submit(task);
    assertSame(task, executor.getSubmittedTasks().get(0));
  }

  @Test
  public void validateContainerWithCustomThreadExecutor() throws Exception {
    ExecutorServiceSpy executor = new ExecutorServiceSpy();
    configuration.setThreadExecutor(executor);
    ValidationResult result = validateContainer("src/test/resources/testFiles/invalid-containers/two_signatures.bdoc", configuration);
    assertFalse(result.isValid());
    assertEquals(2, executor.getSubmittedTasks().size());  //Two signatures must be validated within a thread pool
  }

  private ValidationResult validateContainer(String containerPath, Configuration configuration) {
    Container container = openContainerBuilder(containerPath).
        withConfiguration(configuration).
        build();
    return container.validate();
  }

  private ContainerBuilder openContainerBuilder(String containerPath) {
    return ContainerBuilder.
        aContainer("BDOC").
        fromExistingFile(containerPath);
  }

  private static class ExecutorServiceSpy extends ThreadPoolExecutor {

    List<Callable> submittedTasks = new ArrayList<>();

    public ExecutorServiceSpy() {
      super(1, 1, 1, TimeUnit.SECONDS, new ArrayBlockingQueue(10));
    }

    @Override
    public <T> Future<T> submit(Callable<T> task) {
      submittedTasks.add(task);
      return super.submit(task);
    }

    public List<Callable> getSubmittedTasks() {
      return submittedTasks;
    }
  }

  private class DummyTask implements Callable<Object> {
    @Override
    public Object call() throws Exception {
      return null;
    }
  }
}
