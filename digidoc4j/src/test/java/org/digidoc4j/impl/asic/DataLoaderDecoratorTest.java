package org.digidoc4j.impl.asic;

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.http.proxy.ProxyProperties;
import org.digidoc4j.Configuration;
import org.digidoc4j.ExternalConnectionType;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;

@RunWith(MockitoJUnitRunner.class)
public class DataLoaderDecoratorTest {

    @Mock
    private Configuration configuration;

    @Mock
    private CommonsDataLoader dataLoader;

    @Test
    public void decorateWithSslSettingsShouldDoNothingWhenSslConfigurationNotEnabled() {
        Mockito.doReturn(false).when(configuration).isSslConfigurationEnabled();
        DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);
        Mockito.verifyZeroInteractions(dataLoader);
    }

    @Test
    public void decorateWithSslSettingsForShouldDoNothingWhenSslConfigurationNotEnabled() {
        for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
            Mockito.doReturn(false).when(configuration).isSslConfigurationEnabled();
            Mockito.doReturn(false).when(configuration).isSslConfigurationEnabledFor(connectionType);
            DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);
            Mockito.verifyZeroInteractions(dataLoader);

            Mockito.reset(configuration, dataLoader);
        }
    }

    @Test
    public void decorateWithSslSettingsShouldApplySslKeystorePathIfConfigured() {
        Mockito.doReturn(true).when(configuration).isSslConfigurationEnabled();
        Mockito.doReturn("sslKeystorePath").when(configuration).getSslKeystorePath();
        Mockito.doReturn(null).when(configuration).getSupportedSslProtocols();
        Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuites();

        DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);
        Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePath("sslKeystorePath");
        Mockito.verifyNoMoreInteractions(dataLoader);
    }

    @Test
    public void decorateWithSslSettingsForShouldApplySslKeystorePathIfConfigured() {
        for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
            Mockito.doReturn(true).when(configuration).isSslConfigurationEnabledFor(connectionType);
            Mockito.doReturn("sslKeystorePath").when(configuration).getSslKeystorePathFor(connectionType);
            Mockito.doReturn(null).when(configuration).getSupportedSslProtocolsFor(connectionType);
            Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuitesFor(connectionType);

            DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);
            Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePath("sslKeystorePath");
            Mockito.verifyNoMoreInteractions(dataLoader);

            Mockito.reset(configuration, dataLoader);
        }
    }

    @Test
    public void decorateWithSslSettingsShouldApplyAllSslKeystoreConfigurationIfPresent() {
        Mockito.doReturn(true).when(configuration).isSslConfigurationEnabled();
        Mockito.doReturn("sslKeystorePath").when(configuration).getSslKeystorePath();
        Mockito.doReturn("sslKeystoreType").when(configuration).getSslKeystoreType();
        Mockito.doReturn("sslKeystorePassword").when(configuration).getSslKeystorePassword();
        Mockito.doReturn(null).when(configuration).getSupportedSslProtocols();
        Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuites();

        DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);
        Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePath("sslKeystorePath");
        Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystoreType("sslKeystoreType");
        Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePassword("sslKeystorePassword");
        Mockito.verifyNoMoreInteractions(dataLoader);
    }

    @Test
    public void decorateWithSslSettingsForShouldApplyAllSslKeystoreConfigurationIfPresent() {
        for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
            Mockito.doReturn(true).when(configuration).isSslConfigurationEnabledFor(connectionType);
            Mockito.doReturn("sslKeystorePath").when(configuration).getSslKeystorePathFor(connectionType);
            Mockito.doReturn("sslKeystoreType").when(configuration).getSslKeystoreTypeFor(connectionType);
            Mockito.doReturn("sslKeystorePassword").when(configuration).getSslKeystorePasswordFor(connectionType);
            Mockito.doReturn(null).when(configuration).getSupportedSslProtocolsFor(connectionType);
            Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuitesFor(connectionType);

            DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);
            Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePath("sslKeystorePath");
            Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystoreType("sslKeystoreType");
            Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePassword("sslKeystorePassword");
            Mockito.verifyNoMoreInteractions(dataLoader);

            Mockito.reset(configuration, dataLoader);
        }
    }

    @Test
    public void decorateWithSslSettingsShouldApplySslTruststorePathIfConfigured() {
        Mockito.doReturn(true).when(configuration).isSslConfigurationEnabled();
        Mockito.doReturn("sslTruststorePath").when(configuration).getSslTruststorePath();
        Mockito.doReturn(null).when(configuration).getSupportedSslProtocols();
        Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuites();

        DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);
        Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePath("sslTruststorePath");
        Mockito.verifyNoMoreInteractions(dataLoader);
    }

    @Test
    public void decorateWithSslSettingsForShouldApplySslTruststorePathIfConfigured() {
        for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
            Mockito.doReturn(true).when(configuration).isSslConfigurationEnabledFor(connectionType);
            Mockito.doReturn("sslTruststorePath").when(configuration).getSslTruststorePathFor(connectionType);
            Mockito.doReturn(null).when(configuration).getSupportedSslProtocolsFor(connectionType);
            Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuitesFor(connectionType);

            DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);
            Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePath("sslTruststorePath");
            Mockito.verifyNoMoreInteractions(dataLoader);

            Mockito.reset(configuration, dataLoader);
        }
    }

    @Test
    public void decorateWithSslSettingsShouldApplyAllSslTruststoreConfigurationIfPresent() {
        Mockito.doReturn(true).when(configuration).isSslConfigurationEnabled();
        Mockito.doReturn("sslTruststorePath").when(configuration).getSslTruststorePath();
        Mockito.doReturn("sslTruststoreType").when(configuration).getSslTruststoreType();
        Mockito.doReturn("sslTruststorePassword").when(configuration).getSslTruststorePassword();
        Mockito.doReturn(null).when(configuration).getSupportedSslProtocols();
        Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuites();

        DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);
        Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePath("sslTruststorePath");
        Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststoreType("sslTruststoreType");
        Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePassword("sslTruststorePassword");
        Mockito.verifyNoMoreInteractions(dataLoader);
    }

    @Test
    public void decorateWithSslSettingsForShouldApplyAllSslTruststoreConfigurationIfPresent() {
        for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
            Mockito.doReturn(true).when(configuration).isSslConfigurationEnabledFor(connectionType);
            Mockito.doReturn("sslTruststorePath").when(configuration).getSslTruststorePathFor(connectionType);
            Mockito.doReturn("sslTruststoreType").when(configuration).getSslTruststoreTypeFor(connectionType);
            Mockito.doReturn("sslTruststorePassword").when(configuration).getSslTruststorePasswordFor(connectionType);
            Mockito.doReturn(null).when(configuration).getSupportedSslProtocolsFor(connectionType);
            Mockito.doReturn(null).when(configuration).getSupportedSslCipherSuitesFor(connectionType);

            DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);
            Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePath("sslTruststorePath");
            Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststoreType("sslTruststoreType");
            Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePassword("sslTruststorePassword");
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
        Mockito.doReturn("sslKeystorePath").when(configuration).getSslKeystorePath();
        Mockito.doReturn("sslKeystoreType").when(configuration).getSslKeystoreType();
        Mockito.doReturn("sslKeystorePassword").when(configuration).getSslKeystorePassword();
        Mockito.doReturn("sslTruststorePath").when(configuration).getSslTruststorePath();
        Mockito.doReturn("sslTruststoreType").when(configuration).getSslTruststoreType();
        Mockito.doReturn("sslTruststorePassword").when(configuration).getSslTruststorePassword();
        Mockito.doReturn(Arrays.asList("sslProtocol1", "sslProtocol2")).when(configuration).getSupportedSslProtocols();
        Mockito.doReturn(Arrays.asList("sslCipherSuite1", "sslCipherSuite2")).when(configuration).getSupportedSslCipherSuites();

        DataLoaderDecorator.decorateWithSslSettings(dataLoader, configuration);

        Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePath("sslKeystorePath");
        Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystoreType("sslKeystoreType");
        Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePassword("sslKeystorePassword");

        Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePath("sslTruststorePath");
        Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststoreType("sslTruststoreType");
        Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePassword("sslTruststorePassword");

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
            Mockito.doReturn("sslKeystorePath").when(configuration).getSslKeystorePathFor(connectionType);
            Mockito.doReturn("sslKeystoreType").when(configuration).getSslKeystoreTypeFor(connectionType);
            Mockito.doReturn("sslKeystorePassword").when(configuration).getSslKeystorePasswordFor(connectionType);
            Mockito.doReturn("sslTruststorePath").when(configuration).getSslTruststorePathFor(connectionType);
            Mockito.doReturn("sslTruststoreType").when(configuration).getSslTruststoreTypeFor(connectionType);
            Mockito.doReturn("sslTruststorePassword").when(configuration).getSslTruststorePasswordFor(connectionType);
            Mockito.doReturn(Arrays.asList("sslProtocol1", "sslProtocol2")).when(configuration).getSupportedSslProtocolsFor(connectionType);
            Mockito.doReturn(Arrays.asList("sslCipherSuite1", "sslCipherSuite2")).when(configuration).getSupportedSslCipherSuitesFor(connectionType);

            DataLoaderDecorator.decorateWithSslSettingsFor(connectionType, dataLoader, configuration);

            Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePath("sslKeystorePath");
            Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystoreType("sslKeystoreType");
            Mockito.verify(dataLoader, Mockito.times(1)).setSslKeystorePassword("sslKeystorePassword");

            Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePath("sslTruststorePath");
            Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststoreType("sslTruststoreType");
            Mockito.verify(dataLoader, Mockito.times(1)).setSslTruststorePassword("sslTruststorePassword");

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
        Mockito.verifyZeroInteractions(dataLoader);
    }

    @Test
    public void decorateWithProxySettingsForShouldDoNothingWhenNetworkProxyNotEnabled() {
        for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
            Mockito.doReturn(false).when(configuration).isNetworkProxyEnabledFor(connectionType);
            DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
            Mockito.verifyZeroInteractions(dataLoader);

            Mockito.reset(configuration, dataLoader);
        }
    }

    @Test
    public void decorateWithProxySettingsShouldApplyHttpHostAndPortIfConfigured() {
        Mockito.doReturn(true).when(configuration).isNetworkProxyEnabled();
        Mockito.doReturn(Integer.valueOf(8073)).when(configuration).getHttpProxyPort();
        Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHost();

        DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
        ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
        assertProxyPropertiesNotConfigured(capturedProxyConfig.getHttpsProperties());

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
            Mockito.doReturn(Integer.valueOf(8073)).when(configuration).getHttpProxyPortFor(connectionType);
            Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHostFor(connectionType);

            DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
            ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
            assertProxyPropertiesNotConfigured(capturedProxyConfig.getHttpsProperties());

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
        Mockito.doReturn(Integer.valueOf(473)).when(configuration).getHttpsProxyPort();
        Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHost();

        DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
        ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
        assertProxyPropertiesNotConfigured(capturedProxyConfig.getHttpProperties());

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
            Mockito.doReturn(Integer.valueOf(473)).when(configuration).getHttpsProxyPortFor(connectionType);
            Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHostFor(connectionType);

            DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
            ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();
            assertProxyPropertiesNotConfigured(capturedProxyConfig.getHttpProperties());

            Assert.assertEquals(473, capturedProxyConfig.getHttpsProperties().getPort());
            Assert.assertEquals("httpsProxyHost", capturedProxyConfig.getHttpsProperties().getHost());
            Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
            Assert.assertNull(capturedProxyConfig.getHttpsProperties().getUser());
            Assert.assertNull(capturedProxyConfig.getHttpsProperties().getPassword());

            Mockito.reset(configuration, dataLoader);
        }
    }

    @Test
    public void decorateWithProxySettingsShouldApplyUserAndPasswordIfConfigured() {
        Mockito.doReturn(true).when(configuration).isNetworkProxyEnabled();
        Mockito.doReturn("proxyUser").when(configuration).getHttpProxyUser();
        Mockito.doReturn("proxyPassword").when(configuration).getHttpProxyPassword();

        DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
        ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();

        Assert.assertEquals(0, capturedProxyConfig.getHttpProperties().getPort());
        Assert.assertNull(capturedProxyConfig.getHttpProperties().getHost());
        Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
        Assert.assertEquals("proxyUser", capturedProxyConfig.getHttpProperties().getUser());
        Assert.assertEquals("proxyPassword", capturedProxyConfig.getHttpProperties().getPassword());

        Assert.assertEquals(0, capturedProxyConfig.getHttpsProperties().getPort());
        Assert.assertNull(capturedProxyConfig.getHttpsProperties().getHost());
        Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
        Assert.assertEquals("proxyUser", capturedProxyConfig.getHttpsProperties().getUser());
        Assert.assertEquals("proxyPassword", capturedProxyConfig.getHttpsProperties().getPassword());
    }

    @Test
    public void decorateWithProxySettingsForShouldApplyUserAndPasswordIfConfigured() {
        for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
            Mockito.doReturn(true).when(configuration).isNetworkProxyEnabledFor(connectionType);
            Mockito.doReturn("proxyUser").when(configuration).getHttpProxyUserFor(connectionType);
            Mockito.doReturn("proxyPassword").when(configuration).getHttpProxyPasswordFor(connectionType);

            DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
            ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();

            Assert.assertEquals(0, capturedProxyConfig.getHttpProperties().getPort());
            Assert.assertNull(capturedProxyConfig.getHttpProperties().getHost());
            Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
            Assert.assertEquals("proxyUser", capturedProxyConfig.getHttpProperties().getUser());
            Assert.assertEquals("proxyPassword", capturedProxyConfig.getHttpProperties().getPassword());

            Assert.assertEquals(0, capturedProxyConfig.getHttpsProperties().getPort());
            Assert.assertNull(capturedProxyConfig.getHttpsProperties().getHost());
            Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
            Assert.assertEquals("proxyUser", capturedProxyConfig.getHttpsProperties().getUser());
            Assert.assertEquals("proxyPassword", capturedProxyConfig.getHttpsProperties().getPassword());

            Mockito.reset(configuration, dataLoader);
        }
    }

    @Test
    public void decorateWithProxySettingsShouldApplyAllConfiguredProxySettings() {
        Mockito.doReturn(true).when(configuration).isNetworkProxyEnabled();
        Mockito.doReturn(Integer.valueOf(8073)).when(configuration).getHttpProxyPort();
        Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHost();
        Mockito.doReturn(Integer.valueOf(473)).when(configuration).getHttpsProxyPort();
        Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHost();
        Mockito.doReturn("proxyUser").when(configuration).getHttpProxyUser();
        Mockito.doReturn("proxyPassword").when(configuration).getHttpProxyPassword();

        DataLoaderDecorator.decorateWithProxySettings(dataLoader, configuration);
        ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();

        Assert.assertEquals(8073, capturedProxyConfig.getHttpProperties().getPort());
        Assert.assertEquals("httpProxyHost", capturedProxyConfig.getHttpProperties().getHost());
        Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
        Assert.assertEquals("proxyUser", capturedProxyConfig.getHttpProperties().getUser());
        Assert.assertEquals("proxyPassword", capturedProxyConfig.getHttpProperties().getPassword());

        Assert.assertEquals(473, capturedProxyConfig.getHttpsProperties().getPort());
        Assert.assertEquals("httpsProxyHost", capturedProxyConfig.getHttpsProperties().getHost());
        Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
        Assert.assertEquals("proxyUser", capturedProxyConfig.getHttpsProperties().getUser());
        Assert.assertEquals("proxyPassword", capturedProxyConfig.getHttpsProperties().getPassword());
    }

    @Test
    public void decorateWithProxySettingsForShouldApplyAllConfiguredProxySettings() {
        for (final ExternalConnectionType connectionType : ExternalConnectionType.values()) {
            Mockito.doReturn(true).when(configuration).isNetworkProxyEnabledFor(connectionType);
            Mockito.doReturn(Integer.valueOf(8073)).when(configuration).getHttpProxyPortFor(connectionType);
            Mockito.doReturn("httpProxyHost").when(configuration).getHttpProxyHostFor(connectionType);
            Mockito.doReturn(Integer.valueOf(473)).when(configuration).getHttpsProxyPortFor(connectionType);
            Mockito.doReturn("httpsProxyHost").when(configuration).getHttpsProxyHostFor(connectionType);
            Mockito.doReturn("proxyUser").when(configuration).getHttpProxyUserFor(connectionType);
            Mockito.doReturn("proxyPassword").when(configuration).getHttpProxyPasswordFor(connectionType);

            DataLoaderDecorator.decorateWithProxySettingsFor(connectionType, dataLoader, configuration);
            ProxyConfig capturedProxyConfig = verifyDataLoaderProxyConfigSetAndCaptureProxyConfig();

            Assert.assertEquals(8073, capturedProxyConfig.getHttpProperties().getPort());
            Assert.assertEquals("httpProxyHost", capturedProxyConfig.getHttpProperties().getHost());
            Assert.assertNull(capturedProxyConfig.getHttpProperties().getExcludedHosts());
            Assert.assertEquals("proxyUser", capturedProxyConfig.getHttpProperties().getUser());
            Assert.assertEquals("proxyPassword", capturedProxyConfig.getHttpProperties().getPassword());

            Assert.assertEquals(473, capturedProxyConfig.getHttpsProperties().getPort());
            Assert.assertEquals("httpsProxyHost", capturedProxyConfig.getHttpsProperties().getHost());
            Assert.assertNull(capturedProxyConfig.getHttpsProperties().getExcludedHosts());
            Assert.assertEquals("proxyUser", capturedProxyConfig.getHttpsProperties().getUser());
            Assert.assertEquals("proxyPassword", capturedProxyConfig.getHttpsProperties().getPassword());

            Mockito.reset(configuration, dataLoader);
        }
    }

    private ProxyConfig verifyDataLoaderProxyConfigSetAndCaptureProxyConfig() {
        ArgumentCaptor<ProxyConfig> argumentCaptor = ArgumentCaptor.forClass(ProxyConfig.class);
        Mockito.verify(dataLoader, Mockito.times(1)).setProxyConfig(argumentCaptor.capture());
        Mockito.verifyNoMoreInteractions(dataLoader);
        return argumentCaptor.getValue();
    }

    private void assertProxyPropertiesNotConfigured(ProxyProperties proxyProperties) {
        Assert.assertEquals(0, proxyProperties.getPort());
        Assert.assertNull(proxyProperties.getExcludedHosts());
        Assert.assertNull(proxyProperties.getHost());
        Assert.assertNull(proxyProperties.getUser());
        Assert.assertNull(proxyProperties.getPassword());
    }

}