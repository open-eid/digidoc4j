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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.exceptions.NotSupportedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Offers functionality for handling DDoc containers.
 */
public class DDocContainer implements Container {

  private static final Logger logger = LoggerFactory.getLogger(DDocContainer.class);

  private DDocFacade jDigiDocFacade;

  /**
   * DDocContainer constructor.
   *
   * @param jDigiDocFacade
   */
  public DDocContainer(DDocFacade jDigiDocFacade) {
    this.jDigiDocFacade = jDigiDocFacade;
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
    return jDigiDocFacade.getDataFiles();
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
    return jDigiDocFacade.getSignatures();
  }

  @Override
  public void removeDataFile(DataFile file) {
    throw new NotSupportedException("Removing data files is not supported anymore for DDoc!");
  }

  @Override
  public void removeSignature(Signature signature) {
    throw new NotSupportedException("Removing data files is not supported anymore for DDoc!");
  }

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {
    throw new NotSupportedException("Extending signature profile is not supported anymore for DDoc!");
  }

  @Override
  public File saveAsFile(String fileName) {
    jDigiDocFacade.save(fileName);
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
    return jDigiDocFacade.validate();
  }

  @Override
  public void setTimeStampToken(DataFile timeStampToken) {
    throw new NotSupportedException("Not for DDOC container");
  }

  /**
   * Prepare signature.
   * After preparing the signature the container will have to be signed as well
   *
   * @param signerCert X509 Certificate to be used for preparing the signature
   * @return Signed info
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public SignedInfo prepareSigning(X509Certificate signerCert) {
    throw new NotSupportedException("Adding new signatures is not supported anymore for DDoc!");
  }

  @Override
  public Configuration getConfiguration() {
    return jDigiDocFacade.getConfiguration();
  }

  /**
   * Return signature profile
   *
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public String getSignatureProfile() {
    return jDigiDocFacade.getSignatureProfile();
  }

  /**
   * Set signature parameters
   *
   * @param signatureParameters Signature parameters. These are  related to the signing location and signer roles
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public void setSignatureParameters(SignatureParameters signatureParameters) {
    throw new NotSupportedException("Adding new signatures is not supported anymore for DDoc!");
  }

  /**
   * Get digest algorithm
   *
   * @return Digest algorithm
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public DigestAlgorithm getDigestAlgorithm() {
    return jDigiDocFacade.getDigestAlgorithm();
  }

  /**
   * Adds a signature to the container.
   *
   * @param signature signature to be added to the container
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public void addRawSignature(byte[] signature) {
    throw new NotSupportedException("Adding new signatures is not supported anymore for DDoc!");
  }

  /**
   * Adds signature from the input stream to the container.
   * For BDOC it throws a NotYetImplementedException().
   *
   * @param signatureStream signature to be added to the container
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public void addRawSignature(InputStream signatureStream) {
    throw new NotSupportedException("Adding new signatures is not supported anymore for DDoc!");
  }

  /**
   * Returns a data file
   *
   * @param index index number of the data file to return
   * @return data file
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public DataFile getDataFile(int index) {
    return jDigiDocFacade.getDataFiles().get(index);
  }

  /**
   * Return the count of DataFile objects
   *
   * @return count of DataFile objects
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public int countDataFiles() {
    return jDigiDocFacade.countDataFiles();
  }

  /**
   * Removes a data file from the container by data file name. Any corresponding signatures will be deleted.
   *
   * @param fileName name of the data file to be removed
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public void removeDataFile(String fileName) {
    throw new NotSupportedException("Removing data files is not supported anymore for DDoc!");
  }

  /**
   * Removes the signature with the given signature id from the container.
   *
   * @param signatureId id of the signature to be removed
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public void removeSignature(int signatureId) {
    throw new NotSupportedException("Removing data files is not supported anymore for DDoc!");
  }

  /**
   * Saves the container to the specified location.
   *
   * @param path file name and path.
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public void save(String path) {
    jDigiDocFacade.save(path);
  }

  /**
   * Saves the container to the java.io.OutputStream.
   *
   * @param out output stream.
   * @see OutputStream
   */
  @Override
  public void save(OutputStream out) {
    jDigiDocFacade.save(out);
  }

  /**
   * Signs all data files in the container.
   *
   * @param signatureToken signatureToken implementation
   * @return signature
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public Signature sign(SignatureToken signatureToken) {
    throw new NotSupportedException("Adding new signatures is not supported anymore for DDoc!");
  }

  /**
   * Signs all data files in the container.
   *
   * @param rawSignature raw signature
   * @return signature
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public Signature signRaw(byte[] rawSignature) {
    throw new NotSupportedException("Adding new signatures is not supported anymore for DDoc!");
  }

  /**
   * Return signature
   *
   * @param index index number of the signature to return
   * @return signature
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public Signature getSignature(int index) {
    return jDigiDocFacade.getSignature(index);
  }

  /**
   * Return the count of Signature objects
   *
   * @return count of Signature objects
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public int countSignatures() {
    return jDigiDocFacade.countSignatures();
  }

  /**
   * Returns document type ASiC or DDOC
   *
   * @return document type
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public DocumentType getDocumentType() {
    return jDigiDocFacade.getDocumentType();
  }

  /**
   * Returns container version in case of DDOC. BDOC does not have a version and it returns null
   *
   * @return version
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public String getVersion() {
    return jDigiDocFacade.getVersion();
  }

  /**
   * Extends signature profile to SignatureProfile
   * *
   *
   * @param profile signature profile
   * @see SignatureProfile
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public void extendTo(SignatureProfile profile) {
    throw new NotSupportedException("Extending signature profile is not supported anymore for DDoc!");
  }

  /**
   * Extends signature profile to @see SignatureProfile
   *
   * @param profile signature profile
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public void setSignatureProfile(SignatureProfile profile) {
    throw new NotSupportedException("Setting signature profile is not supported anymore for DDoc!");
  }

  /**
   *  This method returns Returns DDocFacade.
   *  DDocFacade for handling data files and signatures in a container.
   *
   * @return DDocFacade.
   */
  public DDocFacade getJDigiDocFacade() {
    return jDigiDocFacade;
  }

  /**
   * Returns ddoc format
   *
   * @return format as string
   */
  public String getFormat() {
    return jDigiDocFacade.getFormat();
  }
}
