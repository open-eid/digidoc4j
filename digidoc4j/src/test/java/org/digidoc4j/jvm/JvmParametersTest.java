package org.digidoc4j.jvm;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyProperties;
import org.digidoc4j.impl.asic.DataLoaderDecorator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Created by Andrei on 15.09.2017.
 */

public class JvmParametersTest extends AbstractTest {

  @Test
  public void getProxySystemParamsFromConfig() {
    assertEquals("http.proxyHost", configuration.getHttpProxyHost());
    assertEquals(Integer.valueOf(8800), configuration.getHttpProxyPort());
    assertEquals("https.proxyHost", configuration.getHttpsProxyHost());
    assertEquals(Integer.valueOf(10000), configuration.getHttpsProxyPort());
  }

  @Test
  public void getSSLSystemParamsFromConfig() {
    assertEquals("javax.net.ssl.keyStore", configuration.getSslKeystorePath());
    assertEquals("javax.net.ssl.keyStorePassword", configuration.getSslKeystorePassword());
    assertEquals("javax.net.ssl.trustStore", configuration.getSslTruststorePath());
    assertEquals("javax.net.ssl.trustStorePassword", configuration.getSslTruststorePassword());
  }

  @Test
  public void dataLoaderProxyEnabledTest() {
    CommonsDataLoader dataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    ProxyProperties httpProperties = dataLoader.getProxyConfig().getHttpProperties();
    ProxyProperties httpsProperties = dataLoader.getProxyConfig().getHttpsProperties();
    assertEquals("http.proxyHost", httpProperties.getHost());
    assertEquals(8800, httpProperties.getPort());
    assertEquals("https.proxyHost", httpsProperties.getHost());
    assertEquals(10000, httpsProperties.getPort());
  }

  @Test
  public void dataLoaderHttpsProxyEmptyTest() {
    System.clearProperty("https.proxyHost");
    System.clearProperty("https.proxyPort");
    configuration = new Configuration(Configuration.Mode.TEST);
    CommonsDataLoader dataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    ProxyProperties httpProperties = dataLoader.getProxyConfig().getHttpProperties();
    ProxyProperties httpsProperties = dataLoader.getProxyConfig().getHttpsProperties();
    assertEquals("http.proxyHost", httpProperties.getHost());
    assertEquals(8800, httpProperties.getPort());
    assertNull(httpsProperties);
  }

  @Test
  public void dataLoaderHttpProxyEmptyTest() {
    System.clearProperty("http.proxyHost");
    System.clearProperty("http.proxyPort");
    configuration = new Configuration(Configuration.Mode.TEST);
    CommonsDataLoader dataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    ProxyProperties httpProperties = dataLoader.getProxyConfig().getHttpProperties();
    ProxyProperties httpsProperties = dataLoader.getProxyConfig().getHttpsProperties();
    assertNull(httpProperties);
    assertEquals("https.proxyHost", httpsProperties.getHost());
    assertEquals(10000, httpsProperties.getPort());
  }

  @Test
  public void dataLoaderProxyDisabledTest() {
    System.clearProperty("http.proxyHost");
    System.clearProperty("http.proxyPort");
    System.clearProperty("https.proxyHost");
    System.clearProperty("https.proxyPort");
    configuration = new Configuration(Configuration.Mode.TEST);
    CommonsDataLoader dataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    assertNull(dataLoader.getProxyConfig());
  }

  @Test
  public void getParamsFromJVMAndFilePriorityTest() {
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_jvm_params.yaml");
    assertEquals("http.proxyHost", configuration.getHttpProxyHost());
    assertEquals(Integer.valueOf(8800), configuration.getHttpProxyPort());
    assertEquals("https.proxyHost", configuration.getHttpsProxyHost());
    assertEquals(Integer.valueOf(10000), configuration.getHttpsProxyPort());
    assertEquals("javax.net.ssl.keyStore", configuration.getSslKeystorePath());
    assertEquals("javax.net.ssl.keyStorePassword", configuration.getSslKeystorePassword());
    assertEquals("javax.net.ssl.trustStore", configuration.getSslTruststorePath());
    assertEquals("javax.net.ssl.trustStorePassword", configuration.getSslTruststorePassword());
  }

  @Test
  public void getParamsFromFileJVMNullTest() {
    System.clearProperty("http.proxyHost");
    System.clearProperty("http.proxyPort");
    System.clearProperty("https.proxyHost");
    System.clearProperty("https.proxyPort");
    System.clearProperty("javax.net.ssl.keyStore");
    System.clearProperty("javax.net.ssl.keyStorePassword");
    System.clearProperty("javax.net.ssl.trustStore");
    System.clearProperty("javax.net.ssl.trustStorePassword");
    configuration = new Configuration(Configuration.Mode.TEST);
    configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_jvm_params.yaml");
    assertEquals("http.proxyHost.yaml", configuration.getHttpProxyHost());
    assertEquals(Integer.valueOf(1100), configuration.getHttpProxyPort());
    assertEquals("https.proxyHost.yaml", configuration.getHttpsProxyHost());
    assertEquals(Integer.valueOf(110000), configuration.getHttpsProxyPort());
    assertEquals("sslKeystorePath.yaml", configuration.getSslKeystorePath());
    assertEquals("sslKeystorePassword.yaml", configuration.getSslKeystorePassword());
    assertEquals("sslTruststorePath.yaml", configuration.getSslTruststorePath());
    assertEquals("sslTruststorePassword.yaml", configuration.getSslTruststorePassword());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    // JVM proxy parameters
    System.setProperty("http.proxyHost", "http.proxyHost");
    System.setProperty("http.proxyPort", "8800");
    System.setProperty("https.proxyHost", "https.proxyHost");
    System.setProperty("https.proxyPort", "10000");
    // JVM SSL parameters
    System.setProperty("javax.net.ssl.keyStore", "javax.net.ssl.keyStore");
    System.setProperty("javax.net.ssl.keyStorePassword", "javax.net.ssl.keyStorePassword");
    System.setProperty("javax.net.ssl.trustStore", "javax.net.ssl.trustStore");
    System.setProperty("javax.net.ssl.trustStorePassword", "javax.net.ssl.trustStorePassword");
    configuration = new Configuration(Configuration.Mode.TEST);
  }

}

