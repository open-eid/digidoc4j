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

import static org.apache.commons.lang3.StringUtils.isNotBlank;

import org.digidoc4j.Configuration;
import org.digidoc4j.ExternalConnectionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.http.proxy.ProxyProperties;

import java.util.List;

/**
 * Data loader decorator
 */
public class DataLoaderDecorator {

  private final static Logger logger = LoggerFactory.getLogger(DataLoaderDecorator.class);

  /**
   * @param dataLoader data loader
   * @param configuration configuration
   */
  public static void decorateWithProxySettings(CommonsDataLoader dataLoader, Configuration configuration) {
    if (configuration.isNetworkProxyEnabled()) {
      ProxyConfig proxyConfig = DataLoaderDecorator.create(configuration);
      dataLoader.setProxyConfig(proxyConfig);
    }
  }

  private static ProxyConfig create(Configuration configuration) {
    logger.debug("Creating proxy settings");
    ProxyConfig proxy = new ProxyConfig();

    ProxyProperties httpProxyProperties = new ProxyProperties();
    if (configuration.getHttpProxyPort() != null
        && isNotBlank(configuration.getHttpProxyHost())) {
    httpProxyProperties.setHost(configuration.getHttpProxyHost());
    httpProxyProperties.setPort(configuration.getHttpProxyPort());
    //not implemented
    //httpProxyProperties.setExcludedHosts();
    }

    ProxyProperties httpsProxyProperties = new ProxyProperties();
    if (configuration.getHttpsProxyPort() != null
        && isNotBlank(configuration.getHttpsProxyHost())) {
    httpsProxyProperties.setHost(configuration.getHttpsProxyHost());
    httpsProxyProperties.setPort(configuration.getHttpsProxyPort());
    //not implemented
    //httpsProxyProperties.setExcludedHosts();
    }

    if (isNotBlank(configuration.getHttpProxyUser()) && isNotBlank(configuration.getHttpProxyPassword())) {
      httpProxyProperties.setUser(configuration.getHttpProxyUser());
      httpProxyProperties.setPassword(configuration.getHttpProxyPassword());

      httpsProxyProperties.setUser(configuration.getHttpProxyUser());
      httpsProxyProperties.setPassword(configuration.getHttpProxyPassword());
    }
    proxy.setHttpProperties(httpProxyProperties);
    proxy.setHttpsProperties(httpsProxyProperties);
    return proxy;
  }

  /**
   * @param connectionType type of external connections
   * @param dataLoader data loader
   * @param configuration configuration
   */
  public static void decorateWithProxySettingsFor(ExternalConnectionType connectionType, CommonsDataLoader dataLoader, Configuration configuration) {
    if (configuration.isNetworkProxyEnabledFor(connectionType)) {
      ProxyConfig proxyConfig = DataLoaderDecorator.createFor(connectionType, configuration);
      dataLoader.setProxyConfig(proxyConfig);
    }
  }

  private static ProxyConfig createFor(ExternalConnectionType connectionType, Configuration configuration) {
    logger.debug("Creating proxy settings");
    ProxyConfig proxy = new ProxyConfig();

    ProxyProperties httpProxyProperties = new ProxyProperties();
    if (configuration.getHttpProxyPortFor(connectionType) != null
            && isNotBlank(configuration.getHttpProxyHostFor(connectionType))) {
      httpProxyProperties.setHost(configuration.getHttpProxyHostFor(connectionType));
      httpProxyProperties.setPort(configuration.getHttpProxyPortFor(connectionType));
      //not implemented
      //httpProxyProperties.setExcludedHosts();
    }

    ProxyProperties httpsProxyProperties = new ProxyProperties();
    if (configuration.getHttpsProxyPortFor(connectionType) != null
            && isNotBlank(configuration.getHttpsProxyHostFor(connectionType))) {
      httpsProxyProperties.setHost(configuration.getHttpsProxyHostFor(connectionType));
      httpsProxyProperties.setPort(configuration.getHttpsProxyPortFor(connectionType));
      //not implemented
      //httpsProxyProperties.setExcludedHosts();
    }

    if (isNotBlank(configuration.getHttpProxyUserFor(connectionType)) && isNotBlank(configuration.getHttpProxyPasswordFor(connectionType))) {
      httpProxyProperties.setUser(configuration.getHttpProxyUserFor(connectionType));
      httpProxyProperties.setPassword(configuration.getHttpProxyPasswordFor(connectionType));

      httpsProxyProperties.setUser(configuration.getHttpProxyUserFor(connectionType));
      httpsProxyProperties.setPassword(configuration.getHttpProxyPasswordFor(connectionType));
    }
    proxy.setHttpProperties(httpProxyProperties);
    proxy.setHttpsProperties(httpsProxyProperties);
    return proxy;
  }

  /**
   * @param dataLoader data loader
   * @param configuration configuration
   */
  public static void decorateWithSslSettings(CommonsDataLoader dataLoader, Configuration configuration) {
    if (configuration.isSslConfigurationEnabled()) {
      logger.debug("Configuring SSL");

      if (configuration.getSslKeystorePath() != null) {
        dataLoader.setSslKeystorePath(configuration.getSslKeystorePath());
        if (configuration.getSslKeystoreType() != null) {
          dataLoader.setSslKeystoreType(configuration.getSslKeystoreType());
        }
        if (configuration.getSslKeystorePassword() != null) {
          dataLoader.setSslKeystorePassword(configuration.getSslKeystorePassword());
        }
      }

      if (configuration.getSslTruststorePath() != null) {
        dataLoader.setSslTruststorePath(configuration.getSslTruststorePath());
        if (configuration.getSslTruststoreType() != null) {
          dataLoader.setSslTruststoreType(configuration.getSslTruststoreType());
        }
        if (configuration.getSslTruststorePassword() != null) {
          dataLoader.setSslTruststorePassword(configuration.getSslTruststorePassword());
        }
      }

      if (configuration.getSslProtocol() != null) {
        dataLoader.setSslProtocol(configuration.getSslProtocol());
      }
      if (configuration.getSupportedSslProtocols() != null) {
        List<String> supportedSslProtocols = configuration.getSupportedSslProtocols();
        dataLoader.setSupportedSSLProtocols(supportedSslProtocols.toArray(new String[supportedSslProtocols.size()]));
      }
      if (configuration.getSupportedSslCipherSuites() != null) {
        List<String> supportedSslCipherSuites = configuration.getSupportedSslCipherSuites();
        dataLoader.setSupportedSSLCipherSuites(supportedSslCipherSuites.toArray(new String[supportedSslCipherSuites.size()]));
      }
    }
  }

  /**
   * @param connectionType type of external connections
   * @param dataLoader data loader
   * @param configuration configuration
   */
  public static void decorateWithSslSettingsFor(ExternalConnectionType connectionType, CommonsDataLoader dataLoader, Configuration configuration) {
    if (configuration.isSslConfigurationEnabledFor(connectionType)) {
      logger.debug("Configuring SSL");

      if (configuration.getSslKeystorePathFor(connectionType) != null) {
        dataLoader.setSslKeystorePath(configuration.getSslKeystorePathFor(connectionType));
        if (configuration.getSslKeystoreTypeFor(connectionType) != null) {
          dataLoader.setSslKeystoreType(configuration.getSslKeystoreTypeFor(connectionType));
        }
        if (configuration.getSslKeystorePasswordFor(connectionType) != null) {
          dataLoader.setSslKeystorePassword(configuration.getSslKeystorePasswordFor(connectionType));
        }
      }

      if (configuration.getSslTruststorePathFor(connectionType) != null) {
        dataLoader.setSslTruststorePath(configuration.getSslTruststorePathFor(connectionType));
        if (configuration.getSslTruststoreTypeFor(connectionType) != null) {
          dataLoader.setSslTruststoreType(configuration.getSslTruststoreTypeFor(connectionType));
        }
        if (configuration.getSslTruststorePasswordFor(connectionType) != null) {
          dataLoader.setSslTruststorePassword(configuration.getSslTruststorePasswordFor(connectionType));
        }
      }

      if (configuration.getSslProtocolFor(connectionType) != null) {
        dataLoader.setSslProtocol(configuration.getSslProtocolFor(connectionType));
      }
      if (configuration.getSupportedSslProtocolsFor(connectionType) != null) {
        List<String> supportedSslProtocols = configuration.getSupportedSslProtocolsFor(connectionType);
        dataLoader.setSupportedSSLProtocols(supportedSslProtocols.toArray(new String[supportedSslProtocols.size()]));
      }
      if (configuration.getSupportedSslCipherSuitesFor(connectionType) != null) {
        List<String> supportedSslCipherSuites = configuration.getSupportedSslCipherSuitesFor(connectionType);
        dataLoader.setSupportedSSLCipherSuites(supportedSslCipherSuites.toArray(new String[supportedSslCipherSuites.size()]));
      }
    }
  }
}
