/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.cades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * A wrapper for {@link DSSDocument}s for capturing document name and mimetype updates,
 * and for shielding the wrapped document from those changes.
 */
public class DssDocumentWrapper implements DSSDocument {

  private final DSSDocument dssDocument;

  private String name;
  private MimeType mimeType;

  public DssDocumentWrapper(DSSDocument document) {
    dssDocument = Objects.requireNonNull(document, "Document cannot be null");
    name = document.getName();
    mimeType = document.getMimeType();
  }

  public DSSDocument getWrappedDocument() {
    return dssDocument;
  }

  @Override
  public InputStream openStream() {
    return dssDocument.openStream();
  }

  @Override
  public void writeTo(OutputStream stream) throws IOException {
    dssDocument.writeTo(stream);
  }

  @Override
  public String getName() {
    return name;
  }

  @Override
  public void setName(String name) {
    this.name = name;
  }

  public boolean isNameUpdated() {
    return !StringUtils.equals(dssDocument.getName(), name);
  }

  @Override
  public MimeType getMimeType() {
    return mimeType;
  }

  @Override
  public void setMimeType(MimeType mimeType) {
    this.mimeType = mimeType;
  }

  public boolean isMimeTypeUpdated() {
    return !Objects.equals(dssDocument.getMimeType(), mimeType);
  }

  @Override
  public void save(String filePath) throws IOException {
    dssDocument.save(filePath);
  }

  @Override
  public Digest getDigest(DigestAlgorithm digestAlgorithm) {
    return dssDocument.getDigest(digestAlgorithm);
  }

  @Override
  public byte[] getDigestValue(DigestAlgorithm digestAlgorithm) {
    return dssDocument.getDigestValue(digestAlgorithm);
  }

}
