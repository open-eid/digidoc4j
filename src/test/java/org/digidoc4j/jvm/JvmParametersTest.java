package org.digidoc4j.jvm;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.impl.asic.DataLoaderDecorator;
import org.junit.Assert;
import org.junit.Test;

import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.http.proxy.ProxyProperties;

/**
 * Created by Andrei on 15.09.2017.
 */

public class JvmParametersTest extends AbstractTest {

  @Test
  public void getProxySystemParamsFromConfig() {
    Assert.assertEquals("http.proxyHost", this.configuration.getHttpProxyHost());
    Assert.assertEquals(new Integer(8800), this.configuration.getHttpProxyPort());
    Assert.assertEquals("https.proxyHost", this.configuration.getHttpsProxyHost());
    Assert.assertEquals(new Integer(10000), this.configuration.getHttpsProxyPort());
  }

  @Test
  public void getSSLSystemParamsFromConfig() {
    Assert.assertEquals("javax.net.ssl.keyStore", this.configuration.getSslKeystorePath());
    Assert.assertEquals("javax.net.ssl.keyStorePassword", this.configuration.getSslKeystorePassword());
    Assert.assertEquals("javax.net.ssl.trustStore", this.configuration.getSslTruststorePath());
    Assert.assertEquals("javax.net.ssl.trustStorePassword", this.configuration.getSslTruststorePassword());
  }

  @Test
  public void dataLoaderProxyEnabledTest() {
    CommonsDataLoader dataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettings(dataLoader, this.configuration);
    ProxyProperties httpProperties = dataLoader.getProxyConfig().getHttpProperties();
    ProxyProperties httpsProperties = dataLoader.getProxyConfig().getHttpsProperties();
    Assert.assertEquals("http.proxyHost", httpProperties.getHost());
    Assert.assertEquals(8800, httpProperties.getPort());
    Assert.assertEquals("https.proxyHost", httpsProperties.getHost());
    Assert.assertEquals(10000, httpsProperties.getPort());
  }

  @Test
  public void dataLoaderHttpsProxyEmptyTest() {
    System.clearProperty("https.proxyHost");
    System.clearProperty("https.proxyPort");
    this.configuration = new Configuration(Configuration.Mode.TEST);
    CommonsDataLoader dataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettings(dataLoader, this.configuration);
    ProxyProperties httpProperties = dataLoader.getProxyConfig().getHttpProperties();
    ProxyProperties httpsProperties = dataLoader.getProxyConfig().getHttpsProperties();
    Assert.assertEquals("http.proxyHost", httpProperties.getHost());
    Assert.assertEquals(8800, httpProperties.getPort());
    Assert.assertEquals(null, httpsProperties.getHost());
    Assert.assertEquals(0, httpsProperties.getPort());
  }

  @Test
  public void dataLoaderHttpProxyEmptyTest() {
    System.clearProperty("http.proxyHost");
    System.clearProperty("http.proxyPort");
    this.configuration = new Configuration(Configuration.Mode.TEST);
    CommonsDataLoader dataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettings(dataLoader, this.configuration);
    ProxyProperties httpProperties = dataLoader.getProxyConfig().getHttpProperties();
    ProxyProperties httpsProperties = dataLoader.getProxyConfig().getHttpsProperties();
    Assert.assertEquals(null, httpProperties.getHost());
    Assert.assertEquals(0, httpProperties.getPort());
    Assert.assertEquals("https.proxyHost", httpsProperties.getHost());
    Assert.assertEquals(10000, httpsProperties.getPort());
  }

  @Test
  public void dataLoaderProxyDisabledTest() {
    System.clearProperty("http.proxyHost");
    System.clearProperty("http.proxyPort");
    System.clearProperty("https.proxyHost");
    System.clearProperty("https.proxyPort");
    this.configuration = new Configuration(Configuration.Mode.TEST);
    CommonsDataLoader dataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettings(dataLoader, this.configuration);
    Assert.assertEquals(null, dataLoader.getProxyConfig());
  }

  @Test
  public void getParamsFromJVMAndFilePriorityTest() {
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_jvm_params.yaml");
    Assert.assertEquals("http.proxyHost", this.configuration.getHttpProxyHost());
    Assert.assertEquals(new Integer(8800), this.configuration.getHttpProxyPort());
    Assert.assertEquals("https.proxyHost", this.configuration.getHttpsProxyHost());
    Assert.assertEquals(new Integer(10000), this.configuration.getHttpsProxyPort());
    Assert.assertEquals("javax.net.ssl.keyStore", this.configuration.getSslKeystorePath());
    Assert.assertEquals("javax.net.ssl.keyStorePassword", this.configuration.getSslKeystorePassword());
    Assert.assertEquals("javax.net.ssl.trustStore", this.configuration.getSslTruststorePath());
    Assert.assertEquals("javax.net.ssl.trustStorePassword", this.configuration.getSslTruststorePassword());
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
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_jvm_params.yaml");
    Assert.assertEquals("http.proxyHost.yaml", this.configuration.getHttpProxyHost());
    Assert.assertEquals(new Integer(1100), this.configuration.getHttpProxyPort());
    Assert.assertEquals("https.proxyHost.yaml", this.configuration.getHttpsProxyHost());
    Assert.assertEquals(new Integer(110000), this.configuration.getHttpsProxyPort());
    Assert.assertEquals("sslKeystorePath.yaml", this.configuration.getSslKeystorePath());
    Assert.assertEquals("sslKeystorePassword.yaml", this.configuration.getSslKeystorePassword());
    Assert.assertEquals("sslTruststorePath.yaml", this.configuration.getSslTruststorePath());
    Assert.assertEquals("sslTruststorePassword.yaml", this.configuration.getSslTruststorePassword());
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
    this.configuration = new Configuration(Configuration.Mode.TEST);
  }

}

