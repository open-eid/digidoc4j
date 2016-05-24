/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.digidoc4j.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.proxy.ProxyDao;
import eu.europa.esig.dss.client.http.proxy.ProxyKey;
import eu.europa.esig.dss.client.http.proxy.ProxyPreference;
import eu.europa.esig.dss.client.http.proxy.ProxyPreferenceManager;

public class ProxySettingsCreator {

  private final static Logger logger = LoggerFactory.getLogger(ProxySettingsCreator.class);

  public static ProxyPreferenceManager create(Configuration configuration) {
    logger.debug("Creating proxy settings");
    ProxyPreferenceManager proxy = new ProxyPreferenceManager();
    ProxyDao proxyDao = new HashMapProxyDao();
    proxyDao.update(new ProxyPreference(ProxyKey.HTTP_HOST, configuration.getHttpProxyHost()));
    proxyDao.update(new ProxyPreference(ProxyKey.HTTP_PORT, configuration.getHttpProxyPort().toString()));
    proxyDao.update(new ProxyPreference(ProxyKey.HTTP_ENABLED, "true"));
    proxyDao.update(new ProxyPreference(ProxyKey.HTTPS_HOST, configuration.getHttpProxyHost()));
    proxyDao.update(new ProxyPreference(ProxyKey.HTTPS_PORT, configuration.getHttpProxyPort().toString()));
    proxyDao.update(new ProxyPreference(ProxyKey.HTTPS_ENABLED, "true"));
    proxy.setProxyDao(proxyDao);
    return proxy;
  }

  public static class HashMapProxyDao implements ProxyDao {

    private Map<ProxyKey, ProxyPreference> values = new HashMap<>();

    @Override
    public ProxyPreference get(ProxyKey id) {
      return values.get(id);
    }

    @Override
    public Collection<ProxyPreference> getAll() {
      return values.values();
    }

    @Override
    public void update(ProxyPreference entity) {
      ProxyKey key = entity.getProxyKey();
      values.put(key, entity);
    }
  }
}
