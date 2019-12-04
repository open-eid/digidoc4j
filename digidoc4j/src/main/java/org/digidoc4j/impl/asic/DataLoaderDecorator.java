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
        List<String> supportedSslCipherSuites = (configuration.getSupportedSslCipherSuites());
        dataLoader.setSupportedSSLCipherSuites(supportedSslCipherSuites.toArray(new String[supportedSslCipherSuites.size()]));
      }
    }
  }
}
