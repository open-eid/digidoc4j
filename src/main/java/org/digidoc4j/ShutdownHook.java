package org.digidoc4j;

import java.lang.reflect.Field;
import java.util.concurrent.ExecutorService;

import org.digidoc4j.impl.ConfigurationSingeltonHolder;
import org.digidoc4j.impl.asic.tsl.LazyTslCertificateSource;
import org.digidoc4j.impl.asic.xades.validation.ThreadPoolManager;

import eu.europa.esig.dss.tsl.service.TSLValidationJob;

/**
 * Shutdown hook for clean shutdown. Please register this hook by Runtime.getRuntime().addShutdownHook(new
 * ShutdownHook()) when necessary. This hook works only for limited cases. NB! Currently in experimental status
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
