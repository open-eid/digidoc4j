/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic;

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import org.digidoc4j.Configuration;
import org.digidoc4j.ExternalConnectionType;
import org.digidoc4j.utils.KeyStoreDocument;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;

import static org.mockito.ArgumentMatchers.any;

@RunWith(MockitoJUnitRunner.class)
public class DataLoaderDecoratorTest {

  private static final String KEYSTORE_PATH = "classpath:testFiles/keystores/keystore.jks";
  private static final String TRUSTSTORE_PATH = "classpath:testFiles/keystores/truststore.p12";

  private static final String KEYSTORE_TYPE = "JKS";
  private static final String TRUSTSTORE_TYPE = "PKCS12";

  private static final String KEYSTORE_PASSWORD = "digidoc4j-password";
  private static final String TRUSTSTORE_PASSWORD = "truststore-password";

  @Mock
  private Configuration configuration;

  @Mock
  private CommonsDataLoader dataLoader;

  @Test
  public void decorateWithSslSettingsShouldDoNothingWhenSslConfigurationNotEnabled() {
    Mockito.doReturn(false).when(configuration).isSslConfigurationEnabled();
    DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);
    Mockito.verifyNoInteractions(dataLoader);
  }

  @Test
  public void decorateWithSslSettingsForShouldDoNothingWhenSslConfigurationNotEnabled() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(false).when(configuration).isSslConfigurationEnabled();
      Mockito.doReturn(false).when(configuration).isSslConfigurationEnabledFor(connectionType);
      DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);
      Mockito.verifyNoInteractions(dataLoader);

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithSslSettingsShouldApplySslKeystorePathIfConfigured() {
    Mockito.doReturn(true).when(configuration).isSslConfigurationEnabled();
    Mockito.doReturn(KEYSTORE_PATH).when(configuration).getSslKeystorePath();
    Mockito.doReturn(null).when(configuration).getSupportedSslProtocols();
    Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuites();

    DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);
    Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystore(any(KeyStoreDocument.class));
    Mockito.verifyNoMoreInteractions(dataLoader);
  }

  @Test
  public void decorateWithSslSettingsForShouldApplySslKeystorePathIfConfigured() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isSslConfigurationEnabledFor(connectionType);
      Mockito.doReturn(KEYSTORE_PATH).when(configuration).getSslKeystorePathFor(connectionType);
      Mockito.doReturn(null).when(configuration).getSupportedSslProtocolsFor(connectionType);
      Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuitesFor(connectionType);

      DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);
      Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystore(any(KeyStoreDocument.class));
      Mockito.verifyNoMoreInteractions(dataLoader);

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithSslSettingsShouldApplyAllSslKeystoreConfigurationIfPresent() {
    Mockito.doReturn(true).when(configuration).isSslConfigurationEnabled();
    Mockito.doReturn(KEYSTORE_PATH).when(configuration).getSslKeystorePath();
    Mockito.doReturn(KEYSTORE_TYPE).when(configuration).getSslKeystoreType();
    Mockito.doReturn(KEYSTORE_PASSWORD).when(configuration).getSslKeystorePassword();
    Mockito.doReturn(null).when(configuration).getSupportedSslProtocols();
    Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuites();

    DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);
    Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystore(any(KeyStoreDocument.class));
    Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystoreType(KEYSTORE_TYPE);
    Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePassword(KEYSTORE_PASSWORD);
    Mockito.verifyNoMoreInteractions(dataLoader);
  }

  @Test
  public void decorateWithSslSettingsForShouldApplyAllSslKeystoreConfigurationIfPresent() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isSslConfigurationEnabledFor(connectionType);
      Mockito.doReturn(KEYSTORE_PATH).when(configuration).getSslKeystorePathFor(connectionType);
      Mockito.doReturn(KEYSTORE_TYPE).when(configuration).getSslKeystoreTypeFor(connectionType);
      Mockito.doReturn(KEYSTORE_PASSWORD).when(configuration).getSslKeystorePasswordFor(connectionType);
      Mockito.doReturn(null).when(configuration).getSupportedSslProtocolsFor(connectionType);
      Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuitesFor(connectionType);

      DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);
      Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystore(any(KeyStoreDocument.class));
      Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystoreType(KEYSTORE_TYPE);
      Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePassword(KEYSTORE_PASSWORD);
      Mockito.verifyNoMoreInteractions(dataLoader);

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithSslSettingsShouldApplySslTruststorePathIfConfigured() {
    Mockito.doReturn(true).when(configuration).isSslConfigurationEnabled();
    Mockito.doReturn(TRUSTSTORE_PATH).when(configuration).getSslTruststorePath();
    Mockito.doReturn(null).when(configuration).getSupportedSslProtocols();
    Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuites();

    DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);
    Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststore(any(KeyStoreDocument.class));
    Mockito.verifyNoMoreInteractions(dataLoader);
  }

  @Test
  public void decorateWithSslSettingsForShouldApplySslTruststorePathIfConfigured() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isSslConfigurationEnabledFor(connectionType);
      Mockito.doReturn(TRUSTSTORE_PATH).when(configuration).getSslTruststorePathFor(connectionType);
      Mockito.doReturn(null).when(configuration).getSupportedSslProtocolsFor(connectionType);
      Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuitesFor(connectionType);

      DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);
      Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststore(any(KeyStoreDocument.class));
      Mockito.verifyNoMoreInteractions(dataLoader);

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithSslSettingsShouldApplyAllSslTruststoreConfigurationIfPresent() {
    Mockito.doReturn(true).when(configuration).isSslConfigurationEnabled();
    Mockito.doReturn(TRUSTSTORE_PATH).when(configuration).getSslTruststorePath();
    Mockito.doReturn(TRUSTSTORE_TYPE).when(configuration).getSslTruststoreType();
    Mockito.doReturn(TRUSTSTORE_PASSWORD).when(configuration).getSslTruststorePassword();
    Mockito.doReturn(null).when(configuration).getSupportedSslProtocols();
    Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuites();

    DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);
    Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststore(any(KeyStoreDocument.class));
    Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststoreType(TRUSTSTORE_TYPE);
    Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePassword(TRUSTSTORE_PASSWORD);
    Mockito.verifyNoMoreInteractions(dataLoader);
  }

  @Test
  public void decorateWithSslSettingsForShouldApplyAllSslTruststoreConfigurationIfPresent() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isSslConfigurationEnabledFor(connectionType);
      Mockito.doReturn(TRUSTSTORE_PATH).when(configuration).getSslTruststorePathFor(connectionType);
      Mockito.doReturn(TRUSTSTORE_TYPE).when(configuration).getSslTruststoreTypeFor(connectionType);
      Mockito.doReturn(TRUSTSTORE_PASSWORD).when(configuration).getSslTruststorePasswordFor(connectionType);
      Mockito.doReturn(null).when(configuration).getSupportedSslProtocolsFor(connectionType);
      Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuitesFor(connectionType);

      DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);
      Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststore(any(KeyStoreDocument.class));
      Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststoreType(TRUSTSTORE_TYPE);
      Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePassword(TRUSTSTORE_PASSWORD);
      Mockito.verifyNoMoreInteractions(dataLoader);

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithSslSettingsShouldApplySupportedSslProtocolsIfConfigured() {
    Mockito.doReturn(true).when(configuration).isSslConfigurationEnabled();
    Mockito.doReturn(Arrays.asList("sslProtocol1", "sslProtocol2")).when(configuration).getSupportedSslProtocols();
    Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuites();

    DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);

    ArgumentCaptor<String[]> argumentCaptor = ArgumentCaptor.forClass(String[].class);
    Mockito.verify(dataLoader, Mockito.times(1)).setSupportedSSLProtocols(argumentCaptor.capture());
    Assert.assertArrayEquals(new String[]{"sslProtocol1", "sslProtocol2"}, argumentCaptor.getValue());
    Mockito.verifyNoMoreInteractions(dataLoader);
  }

  @Test
  public void decorateWithSslSettingsForShouldApplySupportedSslProtocolsIfConfigured() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isSslConfigurationEnabledFor(connectionType);
      Mockito.doReturn(Arrays.asList("sslProtocol1", "sslProtocol2")).when(configuration).getSupportedSslProtocolsFor(connectionType);
      Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuitesFor(connectionType);

      DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);

      ArgumentCaptor<String[]> argumentCaptor = ArgumentCaptor.forClass(String[].class);
      Mockito.verify(dataLoader, Mockito.times(1)).setSupportedSSLProtocols(argumentCaptor.capture());
      Assert.assertArrayEquals(new String[]{"sslProtocol1", "sslProtocol2"}, argumentCaptor.getValue());
      Mockito.verifyNoMoreInteractions(dataLoader);

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithSslSettingsShouldApplySupportedSslCipherSuitesIfConfigured() {
    Mockito.doReturn(true).when(configuration).isSslConfigurationEnabled();
    Mockito.doReturn(null).when(configuration).getSupportedSslProtocols();
    Mockito.doReturn(Arrays.asList("sslCipherSuite1", "sslCipherSuite2")).when(configuration).getSupportedSslCipherSuites();

    DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);

    ArgumentCaptor<String[]> argumentCaptor = ArgumentCaptor.forClass(String[].class);
    Mockito.verify(dataLoader, Mockito.times(1)).setSupportedSSLCipherSuites(argumentCaptor.capture());
    Assert.assertArrayEquals(new String[]{"sslCipherSuite1", "sslCipherSuite2"}, argumentCaptor.getValue());
    Mockito.verifyNoMoreInteractions(dataLoader);
  }

  @Test
  public void decorateWithSslSettingsForShouldApplySupportedSslCipherSuitesIfConfigured() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isSslConfigurationEnabledFor(connectionType);
      Mockito.doReturn(null).when(configuration).getSupportedSslProtocolsFor(connectionType);
      Mockito.doReturn(Arrays.asList("sslCipherSuite1", "sslCipherSuite2")).when(configuration).getSupportedSslCipherSuitesFor(connectionType);

      DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);

      ArgumentCaptor<String[]> argumentCaptor = ArgumentCaptor.forClass(String[].class);
      Mockito.verify(dataLoader, Mockito.times(1)).setSupportedSSLCipherSuites(argumentCaptor.capture());
      Assert.assertArrayEquals(new String[]{"sslCipherSuite1", "sslCipherSuite2"}, argumentCaptor.getValue());
      Mockito.verifyNoMoreInteractions(dataLoader);

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithSslSettingsShouldApplyAllConfiguredSslProperties() {
    Mockito.doReturn(true).when(configuration).isSslConfigurationEnabled();
    Mockito.doReturn(KEYSTORE_PATH).when(configuration).getSslKeystorePath();
    Mockito.doReturn(KEYSTORE_TYPE).when(configuration).getSslKeystoreType();
    Mockito.doReturn(KEYSTORE_PASSWORD).when(configuration).getSslKeystorePassword();
    Mockito.doReturn(TRUSTSTORE_PATH).when(configuration).getSslTruststorePath();
    Mockito.doReturn(TRUSTSTORE_TYPE).when(configuration).getSslTruststoreType();
    Mockito.doReturn(TRUSTSTORE_PASSWORD).when(configuration).getSslTruststorePassword();
    Mockito.doReturn(Arrays.asList("sslProtocol1", "sslProtocol2")).when(configuration).getSupportedSslProtocols();
    Mockito.doReturn(Arrays.asList("sslCipherSuite1", "sslCipherSuite2")).when(configuration).getSupportedSslCipherSuites();

    DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);

    Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystore(any(KeyStoreDocument.class));
    Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystoreType(KEYSTORE_TYPE);
    Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePassword(KEYSTORE_PASSWORD);

    Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststore(any(KeyStoreDocument.class));
    Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststoreType(TRUSTSTORE_TYPE);
    Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePassword(TRUSTSTORE_PASSWORD);

    ArgumentCaptor<String[]> protocolsCaptor = ArgumentCaptor.forClass(String[].class);
    Mockito.verify(dataLoader, Mockito.times(1)).setSupportedSSLProtocols(protocolsCaptor.capture());
    Assert.assertArrayEquals(new String[]{"sslProtocol1", "sslProtocol2"}, protocolsCaptor.getValue());

    ArgumentCaptor<String[]> cipherSuitedCaptor = ArgumentCaptor.forClass(String[].class);
    Mockito.verify(dataLoader, Mockito.times(1)).setSupportedSSLCipherSuites(cipherSuitedCaptor.capture());
    Assert.assertArrayEquals(new String[]{"sslCipherSuite1", "sslCipherSuite2"}, cipherSuitedCaptor.getValue());

    Mockito.verifyNoMoreInteractions(dataLoader);
  }

  @Test
  public void decorateWithSslSettingsForShouldApplyAllConfiguredSslProperties() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isSslConfigurationEnabledFor(connectionType);
      Mockito.doReturn(KEYSTORE_PATH).when(configuration).getSslKeystorePathFor(connectionType);
      Mockito.doReturn(KEYSTORE_TYPE).when(configuration).getSslKeystoreTypeFor(connectionType);
      Mockito.doReturn(KEYSTORE_PASSWORD).when(configuration).getSslKeystorePasswordFor(connectionType);
      Mockito.doReturn(TRUSTSTORE_PATH).when(configuration).getSslTruststorePathFor(connectionType);
      Mockito.doReturn(TRUSTSTORE_TYPE).when(configuration).getSslTruststoreTypeFor(connectionType);
      Mockito.doReturn(TRUSTSTORE_PASSWORD).when(configuration).getSslTruststorePasswordFor(connectionType);
      Mockito.doReturn(Arrays.asList("sslProtocol1", "sslProtocol2")).when(configuration).getSupportedSslProtocolsFor(connectionType);
      Mockito.doReturn(Arrays.asList("sslCipherSuite1", "sslCipherSuite2")).when(configuration).getSupportedSslCipherSuitesFor(connectionType);

      DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);

      Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystore(any(KeyStoreDocument.class));
      Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystoreType(KEYSTORE_TYPE);
      Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePassword(KEYSTORE_PASSWORD);

      Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststore(any(KeyStoreDocument.class));
      Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststoreType(TRUSTSTORE_TYPE);
      Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePassword(TRUSTSTORE_PASSWORD);

      ArgumentCaptor<String[]> protocolsCaptor = ArgumentCaptor.forClass(String[].class);
      Mockito.verify(dataLoader, Mockito.times(1)).setSupportedSSLProtocols(protocolsCaptor.capture());
      Assert.assertArrayEquals(new String[]{"sslProtocol1", "sslProtocol2"}, protocolsCaptor.getValue());

      ArgumentCaptor<String[]> cipherSuitedCaptor = ArgumentCaptor.forClass(String[].class);
      Mockito.verify(dataLoader, Mockito.times(1)).setSupportedSSLCipherSuites(cipherSuitedCaptor.capture());
      Assert.assertArrayEquals(new String[]{"sslCipherSuite1", "sslCipherSuite2"}, cipherSuitedCaptor.getValue());

      Mockito.verifyNoMoreInteractions(dataLoader);
      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithProxySettingsShouldDoNothingWhenNetworkProxyNotEnabled() {
    Mockito.doReturn(false).when(configuration).isNetworkProxyEnabled();
    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    Mockito.verifyNoInteractions(dataLoader);
  }

  @Test
  public void decorateWithProxySettingsForShouldDoNothingWhenNetworkProxyNotEnabled() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(false).when(configuration).isNetworkProxyEnabledFor(connectionType);
      DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
      Mockito.verifyNoInteractions(dataLoader);

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithProxySettingsShouldApplyNullConfigIfHostIsNotConfigured() {
    Mockito.doReturn(true).when(configuration).isNetworkProxyEnabled();
    Mockito.doReturn(8073).when(configuration).getHttpProxyPort();
    Mockito.doReturn("httpProxyUser").when(configuration).getHttpProxyUser();
    Mockito.doReturn("httpProxyPassword").when(configuration).getHttpProxyPassword();
    Mockito.doReturn(473).when(configuration).getHttpsProxyPort();
    Mockito.doReturn("httpsProxyUser").when(configuration).getHttpsProxyUser();
    Mockito.doReturn("httpsProxyPassword").when(configuration).getHttpsProxyPassword();

    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
    Assert.assertNull(capturedProxyConfig);
  }

  @Test
  public void decorateWithProxySettingsForShouldApplyNullConfigIfHostIsNotConfigured() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isNetworkProxyEnabledFor(connectionType);
      Mockito.doReturn(8073).when(configuration).getHttpProxyPortFor(connectionType);
      Mockito.doReturn("httpProxyUser").when(configuration).getHttpProxyUserFor(connectionType);
      Mockito.doReturn("httpProxyPassword").when(configuration).getHttpProxyPasswordFor(connectionType);
      Mockito.doReturn(473).when(configuration).getHttpsProxyPortFor(connectionType);
      Mockito.doReturn("httpsProxyUser").when(configuration).getHttpsProxyUserFor(connectionType);
      Mockito.doReturn("httpsProxyPassword").when(configuration).getHttpsProxyPasswordFor(connectionType);

      DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
      ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
      Assert.assertNull(capturedProxyConfig);

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithProxySettingsShouldApplyNullConfigIfPortIsNotConfigured() {
    Mockito.doReturn(true).when(configuration).isNetworkProxyEnabled();
    Mockito.doReturn(null).when(configuration).getHttpProxyPort();
    Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHost();
    Mockito.doReturn("httpProxyUser").when(configuration).getHttpProxyUser();
    Mockito.doReturn("httpProxyPassword").when(configuration).getHttpProxyPassword();
    Mockito.doReturn(null).when(configuration).getHttpsProxyPort();
    Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHost();
    Mockito.doReturn("httpsProxyUser").when(configuration).getHttpsProxyUser();
    Mockito.doReturn("httpsProxyPassword").when(configuration).getHttpsProxyPassword();

    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
    Assert.assertNull(capturedProxyConfig);
  }

  @Test
  public void decorateWithProxySettingsForShouldApplyNullConfigIfPortIsNotConfigured() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isNetworkProxyEnabledFor(connectionType);
      Mockito.doReturn(null).when(configuration).getHttpProxyPortFor(connectionType);
      Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHostFor(connectionType);
      Mockito.doReturn("httpProxyUser").when(configuration).getHttpProxyUserFor(connectionType);
      Mockito.doReturn("httpProxyPassword").when(configuration).getHttpProxyPasswordFor(connectionType);
      Mockito.doReturn(null).when(configuration).getHttpsProxyPortFor(connectionType);
      Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHostFor(connectionType);
      Mockito.doReturn("httpsProxyUser").when(configuration).getHttpsProxyUserFor(connectionType);
      Mockito.doReturn("httpsProxyPassword").when(configuration).getHttpsProxyPasswordFor(connectionType);

      DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
      ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
      Assert.assertNull(capturedProxyConfig);

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithProxySettingsShouldApplyHttpHostAndPortIfConfigured() {
    Mockito.doReturn(true).when(configuration).isNetworkProxyEnabled();
    Mockito.doReturn(8073).when(configuration).getHttpProxyPort();
    Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHost();

    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
    Assert.assertNotNull(capturedProxyConfig.getHttpProperties());
    Assert.assertNull(capturedProxyConfig.getHttpsProperties());

    Assert.assertEquals(8073, capturedProxyConfig.getHttpProperties().getPort());
    Assert.assertEquals("httpProxyHost", capturedProxyConfig.getHttpProperties().getHost());
    Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
    Assert.assertNull(capturedProxyConfig.getHttpProperties().getUser());
    Assert.assertNull(capturedProxyConfig.getHttpProperties().getPassword());
  }

  @Test
  public void decorateWithProxySettingsForShouldApplyHttpHostAndPortIfConfigured() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isNetworkProxyEnabledFor(connectionType);
      Mockito.doReturn(8073).when(configuration).getHttpProxyPortFor(connectionType);
      Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHostFor(connectionType);

      DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
      ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
      Assert.assertNotNull(capturedProxyConfig.getHttpProperties());
      Assert.assertNull(capturedProxyConfig.getHttpsProperties());

      Assert.assertEquals(8073, capturedProxyConfig.getHttpProperties().getPort());
      Assert.assertEquals("httpProxyHost", capturedProxyConfig.getHttpProperties().getHost());
      Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
      Assert.assertNull(capturedProxyConfig.getHttpProperties().getUser());
      Assert.assertNull(capturedProxyConfig.getHttpProperties().getPassword());

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithProxySettingsShouldApplyHttpsHostAndPortIfConfigured() {
    Mockito.doReturn(true).when(configuration).isNetworkProxyEnabled();
    Mockito.doReturn(473).when(configuration).getHttpsProxyPort();
    Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHost();

    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
    Assert.assertNull(capturedProxyConfig.getHttpProperties());
    Assert.assertNotNull(capturedProxyConfig.getHttpsProperties());

    Assert.assertEquals(473, capturedProxyConfig.getHttpsProperties().getPort());
    Assert.assertEquals("httpsProxyHost", capturedProxyConfig.getHttpsProperties().getHost());
    Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
    Assert.assertNull(capturedProxyConfig.getHttpsProperties().getUser());
    Assert.assertNull(capturedProxyConfig.getHttpsProperties().getPassword());
  }

  @Test
  public void decorateWithProxySettingsForShouldApplyHttpsHostAndPortIfConfigured() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isNetworkProxyEnabledFor(connectionType);
      Mockito.doReturn(473).when(configuration).getHttpsProxyPortFor(connectionType);
      Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHostFor(connectionType);

      DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
      ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
      Assert.assertNull(capturedProxyConfig.getHttpProperties());
      Assert.assertNotNull(capturedProxyConfig.getHttpsProperties());

      Assert.assertEquals(473, capturedProxyConfig.getHttpsProperties().getPort());
      Assert.assertEquals("httpsProxyHost", capturedProxyConfig.getHttpsProperties().getHost());
      Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
      Assert.assertNull(capturedProxyConfig.getHttpsProperties().getUser());
      Assert.assertNull(capturedProxyConfig.getHttpsProperties().getPassword());

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithProxySettingsShouldApplyHttpUserAndPasswordIfConfigured() {
    Mockito.doReturn(true).when(configuration).isNetworkProxyEnabled();
    Mockito.doReturn(8073).when(configuration).getHttpProxyPort();
    Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHost();
    Mockito.doReturn("httpProxyUser").when(configuration).getHttpProxyUser();
    Mockito.doReturn("httpProxyPassword").when(configuration).getHttpProxyPassword();

    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
    Assert.assertNotNull(capturedProxyConfig.getHttpProperties());
    Assert.assertNull(capturedProxyConfig.getHttpsProperties());

    Assert.assertEquals(8073, capturedProxyConfig.getHttpProperties().getPort());
    Assert.assertEquals("httpProxyHost", capturedProxyConfig.getHttpProperties().getHost());
    Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
    Assert.assertEquals("httpProxyUser", capturedProxyConfig.getHttpProperties().getUser());
    Assert.assertEquals("httpProxyPassword", capturedProxyConfig.getHttpProperties().getPassword());
  }

  @Test
  public void decorateWithProxySettingsForShouldApplyHttpUserAndPasswordIfConfigured() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isNetworkProxyEnabledFor(connectionType);
      Mockito.doReturn(8073).when(configuration).getHttpProxyPortFor(connectionType);
      Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHostFor(connectionType);
      Mockito.doReturn("httpProxyUser").when(configuration).getHttpProxyUserFor(connectionType);
      Mockito.doReturn("httpProxyPassword").when(configuration).getHttpProxyPasswordFor(connectionType);

      DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
      ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
      Assert.assertNotNull(capturedProxyConfig.getHttpProperties());
      Assert.assertNull(capturedProxyConfig.getHttpsProperties());

      Assert.assertEquals(8073, capturedProxyConfig.getHttpProperties().getPort());
      Assert.assertEquals("httpProxyHost", capturedProxyConfig.getHttpProperties().getHost());
      Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
      Assert.assertEquals("httpProxyUser", capturedProxyConfig.getHttpProperties().getUser());
      Assert.assertEquals("httpProxyPassword", capturedProxyConfig.getHttpProperties().getPassword());

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithProxySettingsShouldApplyHttpsUserAndPasswordIfConfigured() {
    Mockito.doReturn(true).when(configuration).isNetworkProxyEnabled();
    Mockito.doReturn(473).when(configuration).getHttpsProxyPort();
    Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHost();
    Mockito.doReturn("httpsProxyUser").when(configuration).getHttpsProxyUser();
    Mockito.doReturn("httpsProxyPassword").when(configuration).getHttpsProxyPassword();

    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
    Assert.assertNull(capturedProxyConfig.getHttpProperties());
    Assert.assertNotNull(capturedProxyConfig.getHttpsProperties());

    Assert.assertEquals(473, capturedProxyConfig.getHttpsProperties().getPort());
    Assert.assertEquals("httpsProxyHost", capturedProxyConfig.getHttpsProperties().getHost());
    Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
    Assert.assertEquals("httpsProxyUser", capturedProxyConfig.getHttpsProperties().getUser());
    Assert.assertEquals("httpsProxyPassword", capturedProxyConfig.getHttpsProperties().getPassword());
  }

  @Test
  public void decorateWithProxySettingsForShouldApplyHttpsUserAndPasswordIfConfigured() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isNetworkProxyEnabledFor(connectionType);
      Mockito.doReturn(473).when(configuration).getHttpsProxyPortFor(connectionType);
      Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHostFor(connectionType);
      Mockito.doReturn("httpsProxyUser").when(configuration).getHttpsProxyUserFor(connectionType);
      Mockito.doReturn("httpsProxyPassword").when(configuration).getHttpsProxyPasswordFor(connectionType);

      DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
      ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
      Assert.assertNull(capturedProxyConfig.getHttpProperties());
      Assert.assertNotNull(capturedProxyConfig.getHttpsProperties());

      Assert.assertEquals(473, capturedProxyConfig.getHttpsProperties().getPort());
      Assert.assertEquals("httpsProxyHost", capturedProxyConfig.getHttpsProperties().getHost());
      Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
      Assert.assertEquals("httpsProxyUser", capturedProxyConfig.getHttpsProperties().getUser());
      Assert.assertEquals("httpsProxyPassword", capturedProxyConfig.getHttpsProperties().getPassword());

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithProxySettingsShouldApplyAllButHttpUserAndPasswordIfNotConfigured() {
    Mockito.doReturn(true).when(configuration).isNetworkProxyEnabled();
    Mockito.doReturn(8073).when(configuration).getHttpProxyPort();
    Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHost();
    Mockito.doReturn(473).when(configuration).getHttpsProxyPort();
    Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHost();
    Mockito.doReturn("httpsProxyUser").when(configuration).getHttpsProxyUser();
    Mockito.doReturn("httpsProxyPassword").when(configuration).getHttpsProxyPassword();

    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
    Assert.assertNotNull(capturedProxyConfig.getHttpProperties());
    Assert.assertNotNull(capturedProxyConfig.getHttpsProperties());

    Assert.assertEquals(8073, capturedProxyConfig.getHttpProperties().getPort());
    Assert.assertEquals("httpProxyHost", capturedProxyConfig.getHttpProperties().getHost());
    Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
    Assert.assertNull(capturedProxyConfig.getHttpProperties().getUser());
    Assert.assertNull(capturedProxyConfig.getHttpProperties().getPassword());

    Assert.assertEquals(473, capturedProxyConfig.getHttpsProperties().getPort());
    Assert.assertEquals("httpsProxyHost", capturedProxyConfig.getHttpsProperties().getHost());
    Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
    Assert.assertEquals("httpsProxyUser", capturedProxyConfig.getHttpsProperties().getUser());
    Assert.assertEquals("httpsProxyPassword", capturedProxyConfig.getHttpsProperties().getPassword());
  }

  @Test
  public void decorateWithProxySettingsForShouldApplyAllButHttpUserAndPasswordIfNotConfigured() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isNetworkProxyEnabledFor(connectionType);
      Mockito.doReturn(8073).when(configuration).getHttpProxyPortFor(connectionType);
      Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHostFor(connectionType);
      Mockito.doReturn(473).when(configuration).getHttpsProxyPortFor(connectionType);
      Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHostFor(connectionType);
      Mockito.doReturn("httpsProxyUser").when(configuration).getHttpsProxyUserFor(connectionType);
      Mockito.doReturn("httpsProxyPassword").when(configuration).getHttpsProxyPasswordFor(connectionType);

      DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
      ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
      Assert.assertNotNull(capturedProxyConfig.getHttpProperties());
      Assert.assertNotNull(capturedProxyConfig.getHttpsProperties());

      Assert.assertEquals(8073, capturedProxyConfig.getHttpProperties().getPort());
      Assert.assertEquals("httpProxyHost", capturedProxyConfig.getHttpProperties().getHost());
      Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
      Assert.assertNull(capturedProxyConfig.getHttpProperties().getUser());
      Assert.assertNull(capturedProxyConfig.getHttpProperties().getPassword());

      Assert.assertEquals(473, capturedProxyConfig.getHttpsProperties().getPort());
      Assert.assertEquals("httpsProxyHost", capturedProxyConfig.getHttpsProperties().getHost());
      Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
      Assert.assertEquals("httpsProxyUser", capturedProxyConfig.getHttpsProperties().getUser());
      Assert.assertEquals("httpsProxyPassword", capturedProxyConfig.getHttpsProperties().getPassword());

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithProxySettingsShouldApplyAllButHttpsUserAndPasswordIfNotConfigured() {
    Mockito.doReturn(true).when(configuration).isNetworkProxyEnabled();
    Mockito.doReturn(8073).when(configuration).getHttpProxyPort();
    Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHost();
    Mockito.doReturn("httpProxyUser").when(configuration).getHttpProxyUser();
    Mockito.doReturn("httpProxyPassword").when(configuration).getHttpProxyPassword();
    Mockito.doReturn(473).when(configuration).getHttpsProxyPort();
    Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHost();

    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
    Assert.assertNotNull(capturedProxyConfig.getHttpProperties());
    Assert.assertNotNull(capturedProxyConfig.getHttpsProperties());

    Assert.assertEquals(8073, capturedProxyConfig.getHttpProperties().getPort());
    Assert.assertEquals("httpProxyHost", capturedProxyConfig.getHttpProperties().getHost());
    Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
    Assert.assertEquals("httpProxyUser", capturedProxyConfig.getHttpProperties().getUser());
    Assert.assertEquals("httpProxyPassword", capturedProxyConfig.getHttpProperties().getPassword());

    Assert.assertEquals(473, capturedProxyConfig.getHttpsProperties().getPort());
    Assert.assertEquals("httpsProxyHost", capturedProxyConfig.getHttpsProperties().getHost());
    Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
    Assert.assertNull(capturedProxyConfig.getHttpsProperties().getUser());
    Assert.assertNull(capturedProxyConfig.getHttpsProperties().getPassword());
  }

  @Test
  public void decorateWithProxySettingsForShouldApplyAllButHttpsUserAndPasswordIfNotConfigured() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isNetworkProxyEnabledFor(connectionType);
      Mockito.doReturn(8073).when(configuration).getHttpProxyPortFor(connectionType);
      Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHostFor(connectionType);
      Mockito.doReturn("httpProxyUser").when(configuration).getHttpProxyUserFor(connectionType);
      Mockito.doReturn("httpProxyPassword").when(configuration).getHttpProxyPasswordFor(connectionType);
      Mockito.doReturn(473).when(configuration).getHttpsProxyPortFor(connectionType);
      Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHostFor(connectionType);

      DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
      ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
      Assert.assertNotNull(capturedProxyConfig.getHttpProperties());
      Assert.assertNotNull(capturedProxyConfig.getHttpsProperties());

      Assert.assertEquals(8073, capturedProxyConfig.getHttpProperties().getPort());
      Assert.assertEquals("httpProxyHost", capturedProxyConfig.getHttpProperties().getHost());
      Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
      Assert.assertEquals("httpProxyUser", capturedProxyConfig.getHttpProperties().getUser());
      Assert.assertEquals("httpProxyPassword", capturedProxyConfig.getHttpProperties().getPassword());

      Assert.assertEquals(473, capturedProxyConfig.getHttpsProperties().getPort());
      Assert.assertEquals("httpsProxyHost", capturedProxyConfig.getHttpsProperties().getHost());
      Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
      Assert.assertNull(capturedProxyConfig.getHttpsProperties().getUser());
      Assert.assertNull(capturedProxyConfig.getHttpsProperties().getPassword());

      Mockito.reset(configuration, dataLoader);
    }
  }

  @Test
  public void decorateWithProxySettingsShouldApplyAllConfiguredProxySettings() {
    Mockito.doReturn(true).when(configuration).isNetworkProxyEnabled();
    Mockito.doReturn(8073).when(configuration).getHttpProxyPort();
    Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHost();
    Mockito.doReturn("httpProxyUser").when(configuration).getHttpProxyUser();
    Mockito.doReturn("httpProxyPassword").when(configuration).getHttpProxyPassword();
    Mockito.doReturn(473).when(configuration).getHttpsProxyPort();
    Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHost();
    Mockito.doReturn("httpsProxyUser").when(configuration).getHttpsProxyUser();
    Mockito.doReturn("httpsProxyPassword").when(configuration).getHttpsProxyPassword();

    DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
    ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
    Assert.assertNotNull(capturedProxyConfig.getHttpProperties());
    Assert.assertNotNull(capturedProxyConfig.getHttpsProperties());

    Assert.assertEquals(8073, capturedProxyConfig.getHttpProperties().getPort());
    Assert.assertEquals("httpProxyHost", capturedProxyConfig.getHttpProperties().getHost());
    Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
    Assert.assertEquals("httpProxyUser", capturedProxyConfig.getHttpProperties().getUser());
    Assert.assertEquals("httpProxyPassword", capturedProxyConfig.getHttpProperties().getPassword());

    Assert.assertEquals(473, capturedProxyConfig.getHttpsProperties().getPort());
    Assert.assertEquals("httpsProxyHost", capturedProxyConfig.getHttpsProperties().getHost());
    Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
    Assert.assertEquals("httpsProxyUser", capturedProxyConfig.getHttpsProperties().getUser());
    Assert.assertEquals("httpsProxyPassword", capturedProxyConfig.getHttpsProperties().getPassword());
  }

  @Test
  public void decorateWithProxySettingsForShouldApplyAllConfiguredProxySettings() {
    for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
      Mockito.doReturn(true).when(configuration).isNetworkProxyEnabledFor(connectionType);
      Mockito.doReturn(8073).when(configuration).getHttpProxyPortFor(connectionType);
      Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHostFor(connectionType);
      Mockito.doReturn("httpProxyUser").when(configuration).getHttpProxyUserFor(connectionType);
      Mockito.doReturn("httpProxyPassword").when(configuration).getHttpProxyPasswordFor(connectionType);
      Mockito.doReturn(473).when(configuration).getHttpsProxyPortFor(connectionType);
      Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHostFor(connectionType);
      Mockito.doReturn("httpsProxyUser").when(configuration).getHttpsProxyUserFor(connectionType);
      Mockito.doReturn("httpsProxyPassword").when(configuration).getHttpsProxyPasswordFor(connectionType);

      DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
      ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
      Assert.assertNotNull(capturedProxyConfig.getHttpProperties());
      Assert.assertNotNull(capturedProxyConfig.getHttpsProperties());

      Assert.assertEquals(8073, capturedProxyConfig.getHttpProperties().getPort());
      Assert.assertEquals("httpProxyHost", capturedProxyConfig.getHttpProperties().getHost());
      Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
      Assert.assertEquals("httpProxyUser", capturedProxyConfig.getHttpProperties().getUser());
      Assert.assertEquals("httpProxyPassword", capturedProxyConfig.getHttpProperties().getPassword());

      Assert.assertEquals(473, capturedProxyConfig.getHttpsProperties().getPort());
      Assert.assertEquals("httpsProxyHost", capturedProxyConfig.getHttpsProperties().getHost());
      Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
      Assert.assertEquals("httpsProxyUser", capturedProxyConfig.getHttpsProperties().getUser());
      Assert.assertEquals("httpsProxyPassword", capturedProxyConfig.getHttpsProperties().getPassword());

      Mockito.reset(configuration, dataLoader);
    }
  }

  private ProxyConfig verifyDataLoaderProxyConfigSetAndCaptureProxyConfig() {
    ArgumentCaptor<ProxyConfig> argumentCaptor = ArgumentCaptor.forClass(ProxyConfig.class);
    Mockito.verify(dataLoader, Mockito.times(1)).setProxyConfig(argumentCaptor.capture());
    Mockito.verifyNoMoreInteractions(dataLoader);
    return argumentCaptor.getValue();
  }

}