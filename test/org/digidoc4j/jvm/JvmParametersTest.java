package org.digidoc4j.jvm;

import static org.digidoc4j.Configuration.Mode.TEST;

import org.digidoc4j.Configuration;
import org.digidoc4j.impl.bdoc.DataLoaderDecorator;
import org.junit.Test;

import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;

import static org.junit.Assert.*;

import org.apache.commons.lang3.StringUtils;

/**
 * Created by Andrei on 14.09.2017.
 */
public class JvmParametersTest {
  public void setUp() {
    // JVM proxy parameters
    System.setProperty("http.proxyHost", "http.proxyHost");
    System.setProperty("http.proxyPort", "8800");
    System.setProperty("https.proxyHost", "https.proxyHost");
    System.setProperty("https.proxyPort", "10000");

    // JVM SSL parameters
    System.setProperty("javax.net.ssl.keyStore", "javax.net.ssl.keyStore");
    System.setProperty("javax.net.ssl.keyStorePassword",
        "javax.net.ssl.keyStorePassword");
    System.setProperty("javax.net.ssl.trustStore", "javax.net.ssl.trustStore");
    System.setProperty("javax.net.ssl.trustStorePassword",
        "javax.net.ssl.trustStorePassword");
  }

  @Test
  public void getProxySystemParamsFromConfig() {
    setUp();

    Configuration configuration = new Configuration(TEST);

    assertEquals("http.proxyHost", configuration.getHttpProxyHost());
    assertEquals(new Integer(8800), configuration.getHttpProxyPort());
    assertEquals("https.proxyHost", configuration.getHttpsProxyHost());
    assertEquals(new Integer(10000), configuration.getHttpsProxyPort());
  }

  @Test
  public void getSSLSystemParamsFromConfig() {
    setUp();

    Configuration configuration = new Configuration(TEST);

    assertEquals("javax.net.ssl.keyStore", configuration.getSslKeystorePath());
    assertEquals("javax.net.ssl.keyStorePassword",
        configuration.getSslKeystorePassword());
    assertEquals("javax.net.ssl.trustStore",
        configuration.getSslTruststorePath());
    assertEquals("javax.net.ssl.trustStorePassword",
        configuration.getSslTruststorePassword());
  }

  @Test
  public void dataLoaderProxyEnabledTest() {
    setUp();

    Configuration configuration = new Configuration(TEST);
    CommonsDataLoader dataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);

    assertEquals("http.proxyHost",
        dataLoader.getProxyPreferenceManager().getHttpHost());
    assertEquals(new Long(8800),
        dataLoader.getProxyPreferenceManager().getHttpPort());
    assertEquals("https.proxyHost",
        dataLoader.getProxyPreferenceManager().getHttpsHost());
    assertEquals(new Long(10000),
        dataLoader.getProxyPreferenceManager().getHttpsPort());
    assertEquals(Boolean.TRUE,
        dataLoader.getProxyPreferenceManager().isHttpEnabled());
    assertEquals(Boolean.TRUE,
        dataLoader.getProxyPreferenceManager().isHttpsEnabled());

  }

  @Test
  public void dataLoaderHttpsProxyEmptyTest() {
    setUp();

    System.clearProperty("https.proxyHost");
    System.clearProperty("https.proxyPort");

    Configuration configuration = new Configuration(TEST);
    CommonsDataLoader dataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);

    assertEquals("http.proxyHost", dataLoader.getProxyPreferenceManager().getHttpHost());
    assertEquals(new Long(8800), dataLoader.getProxyPreferenceManager().getHttpPort());
    assertEquals(StringUtils.EMPTY, dataLoader.getProxyPreferenceManager().getHttpsHost());
    assertEquals(null, dataLoader.getProxyPreferenceManager().getHttpsPort());
    assertEquals(Boolean.TRUE, dataLoader.getProxyPreferenceManager().isHttpEnabled());
    assertEquals(Boolean.FALSE, dataLoader.getProxyPreferenceManager().isHttpsEnabled());
  }

  @Test
  public void dataLoaderHttpProxyEmptyTest() {
    setUp();

    System.clearProperty("http.proxyHost");
    System.clearProperty("http.proxyPort");

    Configuration configuration = new Configuration(TEST);
    CommonsDataLoader dataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);

    assertEquals(StringUtils.EMPTY, dataLoader.getProxyPreferenceManager().getHttpHost());
    assertEquals(null, dataLoader.getProxyPreferenceManager().getHttpPort());
    assertEquals("https.proxyHost", dataLoader.getProxyPreferenceManager().getHttpsHost());
    assertEquals(new Long(10000), dataLoader.getProxyPreferenceManager().getHttpsPort());
    assertEquals(Boolean.FALSE, dataLoader.getProxyPreferenceManager().isHttpEnabled());
    assertEquals(Boolean.TRUE, dataLoader.getProxyPreferenceManager().isHttpsEnabled());
  }

  @Test
  public void dataLoaderProxyDisabledTest() {
    setUp();

    System.clearProperty("http.proxyHost");
    System.clearProperty("http.proxyPort");
    System.clearProperty("https.proxyHost");
    System.clearProperty("https.proxyPort");

    Configuration configuration = new Configuration(TEST);
    CommonsDataLoader dataLoader = new CommonsDataLoader();
    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);

    assertEquals(null, dataLoader.getProxyPreferenceManager());
  }

  @Test
  public void getParamsFromJVMAndFilePriorityTest(){
    setUp();

    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.loadConfiguration("testFiles/yaml-configurations/digidoc_test_jvm_params.yaml");

    assertEquals("http.proxyHost", configuration.getHttpProxyHost());
    assertEquals(new Integer(8800), configuration.getHttpProxyPort());
    assertEquals("https.proxyHost", configuration.getHttpsProxyHost());
    assertEquals(new Integer(10000), configuration.getHttpsProxyPort());

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

    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    configuration.loadConfiguration("testFiles/yaml-configurations/digidoc_test_jvm_params.yaml");

    assertEquals("http.proxyHost.yaml", configuration.getHttpProxyHost());
    assertEquals(new Integer(1100), configuration.getHttpProxyPort());
    assertEquals("https.proxyHost.yaml", configuration.getHttpsProxyHost());
    assertEquals(new Integer(110000), configuration.getHttpsProxyPort());

    assertEquals("sslKeystorePath.yaml", configuration.getSslKeystorePath());
    assertEquals("sslKeystorePassword.yaml", configuration.getSslKeystorePassword());
    assertEquals("sslTruststorePath.yaml", configuration.getSslTruststorePath());
    assertEquals("sslTruststorePassword.yaml", configuration.getSslTruststorePassword());
  }


}
