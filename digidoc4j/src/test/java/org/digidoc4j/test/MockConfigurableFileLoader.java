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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;

import java.util.Objects;

public class MockConfigurableFileLoader implements DSSFileLoader {

  @FunctionalInterface
  public interface DocumentGetter {
    DSSDocument getDocument(String url) throws DSSException;
  }

  private DocumentGetter getter = (url) -> {
    throw new UnsupportedOperationException("GET operations not configured");
  };

  @Override
  public DSSDocument getDocument(String url) throws DSSException {
    return getter.getDocument(url);
  }

  public DocumentGetter getDocumentGetter() {
    return getter;
  }

  public void setDocumentGetter(DocumentGetter getter) {
    this.getter = Objects.requireNonNull(getter);
  }

  public MockConfigurableFileLoader withDocumentGetter(DocumentGetter getter) {
    setDocumentGetter(getter);
    return this;
  }

}
