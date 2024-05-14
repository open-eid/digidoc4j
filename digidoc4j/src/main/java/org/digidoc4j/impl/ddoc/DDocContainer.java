/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.ddoc;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.Timestamp;
import org.digidoc4j.exceptions.NotSupportedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

/**
 * Offers functionality for handling DDoc containers.
 */
public class DDocContainer implements Container {

  private static final Logger logger = LoggerFactory.getLogger(DDocContainer.class);
  private static final String NOT_FOR_THIS_CONTAINER = "Not for DDOC container";

  private DDocFacade ddoc4jFacade;

  /**
   * DDocContainer constructor.
   *
   * @param ddoc4jFacade
   */
  public DDocContainer(DDocFacade ddoc4jFacade) {
    this.ddoc4jFacade = ddoc4jFacade;
  }

  @Override
  public DataFile addDataFile(String path, String mimeType) {
    throw new NotSupportedException("Adding new data files is not supported anymore for DDoc!");
  }

  @Override
  public DataFile addDataFile(InputStream is, String fileName, String mimeType) {
    throw new NotSupportedException("Adding new data files is not supported anymore for DDoc!");
  }

  @Override
  public DataFile addDataFile(File file, String mimeType) {
    throw new NotSupportedException("Adding new data files is not supported anymore for DDoc!");
  }

  @Override
  public void addDataFile(DataFile dataFile) {
    throw new NotSupportedException("Adding new data files is not supported anymore for DDoc!");
  }

  @Override
  public void addSignature(Signature signature) {
    throw new NotSupportedException("Adding new signatures is not supported anymore for DDoc!");
  }

  @Override
  public List<DataFile> getDataFiles() {
    return ddoc4jFacade.getDataFiles();
  }

  /**
   * Returns container type "BDOC" or "DDOC"
   */
  @Override
  public String getType() {
    return "DDOC";
  }

  @Override
  public List<Signature> getSignatures() {
    return ddoc4jFacade.getSignatures();
  }

  @Override
  public void removeDataFile(DataFile file) {
    throw new NotSupportedException("Removing data files is not supported anymore for DDoc!");
  }

  @Override
  public void removeSignature(Signature signature) {
    throw new NotSupportedException("Removing signatures is not supported anymore for DDoc!");
  }

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {
    throw new NotSupportedException("Extending signature profile is not supported anymore for DDoc!");
  }

  @Override
  public void extendSignatureProfile(SignatureProfile profile, List<Signature> signaturesToExtend) {
    throw new NotSupportedException("Extending signature profile is not supported anymore for DDoc!");
  }

  @Override
  public File saveAsFile(String fileName) {
    ddoc4jFacade.save(fileName);
    return new File(fileName);
  }

  @Override
  public InputStream saveAsStream() {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    save(outputStream);
    return new ByteArrayInputStream(outputStream.toByteArray());
  }

  @Override
  public ContainerValidationResult validate() {
    return ddoc4jFacade.validate();
  }

  @Override
  public void addTimestamp(Timestamp timestamp) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  public void removeTimestamp(Timestamp timestamp) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  @Deprecated
  public void setTimeStampToken(DataFile timeStampToken) {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  @Deprecated
  public DataFile getTimeStampToken() {
    throw new NotSupportedException(NOT_FOR_THIS_CONTAINER);
  }

  @Override
  public Configuration getConfiguration() {
    return ddoc4jFacade.getConfiguration();
  }

  /**
   * Saves the container to the java.io.OutputStream.
   *
   * @param out output stream.
   * @see OutputStream
   */
  @Override
  public void save(OutputStream out) {
    ddoc4jFacade.save(out);
  }

  /**
   *  This method returns Returns DDocFacade.
   *  DDocFacade for handling data files and signatures in a container.
   *
   * @return DDocFacade.
   */
  public DDocFacade getDDoc4JFacade() {
    return ddoc4jFacade;
  }

  /**
   * Returns ddoc format
   *
   * @return format as string
   */
  public String getFormat() {
    return ddoc4jFacade.getFormat();
  }
}
