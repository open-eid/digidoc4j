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

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.ValidationResult;

public class BDocContainer implements Container {

  private AsicFacade asicFacade;

  public BDocContainer(AsicFacade asicFacade) {
    this.asicFacade = asicFacade;
  }

  public BDocContainer() {
    asicFacade = new AsicFacade();
  }

  public BDocContainer(Configuration configuration) {
    asicFacade = new AsicFacade(configuration);
  }

  @Override
  public DataFile addDataFile(String path, String mimeType) {
    return asicFacade.addDataFile(path, mimeType);
  }

  @Override
  public DataFile addDataFile(InputStream is, String fileName, String mimeType) {
    return asicFacade.addDataFile(is, fileName, mimeType);
  }

  @Override
  public DataFile addDataFile(File file, String mimeType) {
    return asicFacade.addDataFile(file.getPath(), mimeType);
  }

  @Override
  public void addSignature(Signature signature) {
    asicFacade.addSignature(signature);
  }

  @Override
  public List<DataFile> getDataFiles() {
    return asicFacade.getDataFiles();
  }

  @Override
  public String getType() {
    return "BDOC";
  }

  @Override
  public List<Signature> getSignatures() {
    return asicFacade.getSignatures();
  }

  @Override
  public void removeDataFile(DataFile file) {
    asicFacade.removeDataFile(file.getName());
  }

  @Override
  public void removeSignature(Signature signature) {
    asicFacade.removeSignature(signature);
  }

  @Override
  public void extendSignatureProfile(SignatureProfile profile) {
    asicFacade.extendTo(profile);
  }

  @Override
  public File saveAsFile(String filePath) {
    asicFacade.save(filePath);
    return new File(filePath);
  }

  @Override
  public InputStream saveAsStream() {
    return asicFacade.saveAsStream();
  }

  @Override
  public ValidationResult validate() {
    return asicFacade.validate();
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
    return asicFacade.prepareSigning(signerCert);
  }

  /**
   * Return signature profile
   *
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public String getSignatureProfile() {
    return asicFacade.getSignatureProfile();
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
    asicFacade.setSignatureParameters(signatureParameters);
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
    return asicFacade.getDigestAlgorithm();
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
    asicFacade.addRawSignature(signature);
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
    asicFacade.addRawSignature(signatureStream);
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
    return asicFacade.getDataFile(index);
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
    return asicFacade.countDataFiles();
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
    asicFacade.removeDataFile(fileName);
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
    asicFacade.removeSignature(signatureId);
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
    asicFacade.save(path);
  }

  /**
   * Saves the container to the java.io.OutputStream.
   *
   * @param out output stream.
   * @see OutputStream
   * @deprecated will be removed in the future.
   */
  @Override
  @Deprecated
  public void save(OutputStream out) {
    asicFacade.save(out);
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
    return asicFacade.sign(signatureToken);
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
    return asicFacade.signRaw(rawSignature);
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
    return asicFacade.getSignature(index);
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
    return asicFacade.countSignatures();
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
    return asicFacade.getDocumentType();
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
    return asicFacade.getVersion();
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
    asicFacade.extendTo(profile);
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
    asicFacade.setSignatureProfile(profile);
  }

  public AsicFacade getAsicFacade() {
    return asicFacade;
  }
}
