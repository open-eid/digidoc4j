/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.test;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.exception.DSSDataLoaderMultipleException;
import eu.europa.esig.dss.utils.Utils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class MockConfigurableDataLoader implements DataLoader {

  @FunctionalInterface
  public interface Getter {
    byte[] get(String url, Boolean refresh) throws DSSException;
  }

  @FunctionalInterface
  public interface Poster {
    byte[] post(String url, byte[] content) throws DSSException;
  }

  private Getter getter = (url, refresh) -> {
    throw new UnsupportedOperationException("GET operations not configured");
  };
  private Poster poster = (url, content) -> {
    throw new UnsupportedOperationException("POST operations not configured");
  };

  @Override
  public byte[] get(String url) throws DSSException {
    return getter.get(url, null);
  }

  @Override
  public DataAndUrl get(List<String> urlStrings) throws DSSException {
    if (Utils.isCollectionEmpty(urlStrings)) {
      throw new DSSException("Cannot process the GET call. List of URLs is empty!");
    } else {
      Map<String, Throwable> exceptions = new HashMap();
      for (String url : urlStrings) {
        try {
          byte[] bytes = getter.get(url, null);
          if (!Utils.isArrayEmpty(bytes)) {
            return new DataAndUrl(url, bytes);
          }
        } catch (Exception e) {
          exceptions.put(url, e);
        }
      }
      throw new DSSDataLoaderMultipleException(exceptions);
    }
  }

  @Override
  public byte[] get(String url, boolean refresh) throws DSSException {
    return getter.get(url, refresh);
  }

  @Override
  public byte[] post(String url, byte[] content) throws DSSException {
    return poster.post(url, content);
  }

  @Override
  public void setContentType(String contentType) {}

  public Getter getGetter() {
    return getter;
  }

  public void setGetter(Getter getter) {
    this.getter = Objects.requireNonNull(getter);
  }

  public MockConfigurableDataLoader withGetter(Getter getter) {
    setGetter(getter);
    return this;
  }

  public Poster getPoster() {
    return poster;
  }

  public void setPoster(Poster poster) {
    this.poster = Objects.requireNonNull(poster);
  }

  public MockConfigurableDataLoader withPoster(Poster poster) {
    setPoster(poster);
    return this;
  }

}
