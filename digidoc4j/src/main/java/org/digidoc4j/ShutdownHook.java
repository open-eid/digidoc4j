package org.digidoc4j;

import java.lang.reflect.Field;
import java.util.concurrent.ExecutorService;

import org.digidoc4j.impl.ConfigurationSingeltonHolder;
import org.digidoc4j.impl.asic.tsl.LazyTslCertificateSource;
import org.digidoc4j.impl.asic.xades.validation.ThreadPoolManager;

import eu.europa.esig.dss.tsl.service.TSLValidationJob;

/**
 * Shutdown hook for a clean shutdown
 * <p/>
 * There's a good chance that some non-daemon threads handled by some sort of {@link ExecutorService}
 * are preventing JVM from a clean shutdown.
 * <p/>
 * How to use it exactly depends on the situation.
 * <p/>
 * For example when dealing a simple Java "main" program, which has only a single context then
 * registering this hook by {@link Runtime#addShutdownHook(Thread)} should be sufficient.
 * <p/>
 * In case of some sort of webapp in a servlet container where there are multiple levels of contexts
 * the recommended way to use it is to register a {@link javax.servlet.ServletContextListener} and call
 * {@link ShutdownHook#run()} method inside {@link javax.servlet.ServletContextListener#contextDestroyed(ServletContextEvent)}
 * <p/>
 * NB! As the usage method of this hook is dependant on the system/situation and may vary,
 * so in consequence it's still in experimental status
 *
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class ShutdownHook extends Thread {

  @Override
  public void run() {
    this.shutdownDefaultExecutorService();
    if (ConfigurationSingeltonHolder.isInitialized()) {
      Configuration configuration = ConfigurationSingeltonHolder.getInstance();
      this.shutdownExecutorService(configuration);
      this.shutdownTSLValidationJob(configuration);
    }
  }

  /*
   * RESTRICTED METHODS
   */

  private void shutdownDefaultExecutorService() {
    ExecutorService executorService = ThreadPoolManager.getDefaultThreadExecutor();
    if (executorService != null) {
      try {
        executorService.shutdown();
      } catch (Exception e) {
        System.err.println(String.format("Unable to shutdown default executor service: %s", e.getMessage()));
      }
    }
  }

  private void shutdownExecutorService(Configuration configuration) {
    ExecutorService executorService = configuration.getThreadExecutor();
    if (executorService != null) {
      try {
        executorService.shutdown();
      } catch (Exception e) {
        System.err.println(String.format("Unable to shutdown executor service: %s", e.getMessage()));
      }
    }
  }

  private void shutdownTSLValidationJob(Configuration configuration) {
    TSLValidationJob job = null;
    TSLCertificateSource source = configuration.getTSL();
    if (source instanceof LazyTslCertificateSource) {
      job = ((LazyTslCertificateSource) source).getTslLoader().getTslValidationJob();
    } else {
      System.out.println("Unable to shutdown TSL validation job");
    }
    if (job != null) {
      String name = "executorService";
      Field field;
      try {
        field = job.getClass().getDeclaredField(name);
        field.setAccessible(true);
        ((ExecutorService) field.get(job)).shutdown();
      } catch (NoSuchFieldException e) {
        System.err.println(String.format("Executor service field <%s> not found", name));
      } catch (Exception e) {
        System.err.println(String.format("Unable to shutdown TSL validation job: %s", e.getMessage()));
      }
    }
  }

}
