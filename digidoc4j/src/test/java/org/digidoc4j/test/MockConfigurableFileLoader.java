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

  @FunctionalInterface
  public interface Remover {
    boolean remove(String url);
  }

  private DocumentGetter getter = (url) -> {
    throw new UnsupportedOperationException("GET operations not configured");
  };
  private Remover remover = (url) -> {
    throw new UnsupportedOperationException("REMOVE operations not configured");
  };

  @Override
  public DSSDocument getDocument(String url) throws DSSException {
    return getter.getDocument(url);
  }

  @Override
  public boolean remove(String url) {
    return remover.remove(url);
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

  public Remover getRemover() {
    return remover;
  }

  public void setRemover(Remover remover) {
    this.remover = Objects.requireNonNull(remover);
  }

  public MockConfigurableFileLoader withRemover(Remover remover) {
    setRemover(remover);
    return this;
  }

}
