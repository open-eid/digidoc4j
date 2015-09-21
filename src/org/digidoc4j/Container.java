/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.List;

import eu.europa.ec.markt.dss.signature.MimeType;

/**
 * Offers functionality for handling data files and signatures in a container.
 * <p>
 * A container can contain several files and all those files can be signed using signing certificates.
 * A container can only be signed if it contains data files.
 * </p><p>
 * Data files can be added and removed from a container only if the container is not signed.
 * To modify the data list of a signed container by adding or removing datafiles you must first
 * remove all the signatures.
 */
public interface Container extends Serializable {

  /**
   * Adds a data file from the file system to the container.
   * <p>
   * Note:
   * Data files can be removed from a container only after all signatures have been removed.
   * </p>
   *
   * @param path     data file to be added to the container
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   */
  DataFile addDataFile(String path, String mimeType);

  /**
   * Adds a data file from the input stream (i.e. the date file content can be read from the internal memory buffer).
   * <p>
   * Note:
   * Data files can be added to a container only after all signatures have been removed.
   * </p>
   *
   * @param is       input stream from where data is read
   * @param fileName data file name in the container
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   */
  DataFile addDataFile(InputStream is, String fileName, String mimeType);

  DataFile addDataFile(File file, String mimeType);

  void addDataFile(DataFile dataFile);

  void addSignature(Signature signature);

  /**
   * Returns all data files in the container.
   *
   * @return list of all the data files in the container.
   */
  List<DataFile> getDataFiles();

  /**
   * Returns container type "BDOC" or "DDOC"
   */
  String getType();

  /**
   * Returns a list of all signatures in the container.
   *
   * @return list of all signatures
   */
  List<Signature> getSignatures();

  void removeDataFile(DataFile file);

  void removeSignature(Signature signature);

  void extendSignatureProfile(SignatureProfile profile);

  File saveAsFile(String filePath);

  InputStream saveAsStream();

  /**
   * Validate container
   *
   * @return validation result
   */
  ValidationResult validate();

  //Deprecated methods below

  /**
   * Prepare signature.
   * After preparing the signature the container will have to be signed as well
   *
   * @param signerCert X509 Certificate to be used for preparing the signature
   * @return Signed info
   * @deprecated will be removed in the future.
   */
  @Deprecated
  SignedInfo prepareSigning(X509Certificate signerCert);

  /**
   * Document types
   * @deprecated will be removed in the future.
   */
  @Deprecated
  enum DocumentType {
    /**
     * BDOC 2.1 container with mime-type "application/vnd.etsi.asic-e+zip"
     */
    BDOC,
    /**
     * DIGIDOC-XML 1.3 container
     */
    DDOC;

    @Override
    public String toString() {
      if (this == BDOC)
        return MimeType.ASICE.getMimeTypeString();
      return super.toString();
    }
  }

  /**
   * Return signature profile
   * @deprecated will be removed in the future.
   */
  @Deprecated
  String getSignatureProfile();

  /**
   * Set signature parameters
   *
   * @param signatureParameters Signature parameters. These are  related to the signing location and signer roles
   * @deprecated will be removed in the future.
   */
  @Deprecated
  void setSignatureParameters(SignatureParameters signatureParameters);

  /**
   * Get digest algorithm
   *
   * @return Digest algorithm
   * @deprecated will be removed in the future.
   */
  @Deprecated
  DigestAlgorithm getDigestAlgorithm();

  /**
   * Adds a signature to the container.
   *
   * @param signature signature to be added to the container
   * @deprecated will be removed in the future.
   */
  @Deprecated
  void addRawSignature(byte[] signature);

  /**
   * Adds signature from the input stream to the container.
   * For BDOC it throws a NotYetImplementedException().
   *
   * @param signatureStream signature to be added to the container
   * @deprecated will be removed in the future.
   */
  @Deprecated
  void addRawSignature(InputStream signatureStream);

  /**
   * Returns a data file
   *
   * @param index index number of the data file to return
   * @return data file
   * @deprecated will be removed in the future.
   */
  @Deprecated
  DataFile getDataFile(int index);

  /**
   * Return the count of DataFile objects
   * @return count of DataFile objects
   * @deprecated will be removed in the future.
   */
  @Deprecated
  int countDataFiles();

  /**
   * Removes a data file from the container by data file name. Any corresponding signatures will be deleted.
   *
   * @param fileName name of the data file to be removed
   * @deprecated will be removed in the future.
   */
  @Deprecated
  void removeDataFile(String fileName);

  /**
   * Removes the signature with the given signature id from the container.
   *
   * @param signatureId id of the signature to be removed
   * @deprecated will be removed in the future.
   */
  @Deprecated
  void removeSignature(int signatureId);

  /**
   * Saves the container to the specified location.
   *
   * @param path file name and path.
   * @deprecated will be removed in the future.
   */
  @Deprecated
  void save(String path);

  /**
   * Saves the container to the java.io.OutputStream.
   *
   * @param out output stream.
   * @see java.io.OutputStream
   * @deprecated will be removed in the future.
   */
  @Deprecated
  void save(OutputStream out);

  /**
   * Signs all data files in the container.
   *
   * @param signatureToken signatureToken implementation
   * @return signature
   * @deprecated will be removed in the future.
   */
  @Deprecated
  Signature sign(SignatureToken signatureToken);

  /**
   * Signs all data files in the container.
   *
   * @param rawSignature raw signature
   * @return signature
   * @deprecated will be removed in the future.
   */
  @Deprecated
  Signature signRaw(byte[] rawSignature);

  /**
   * Return signature
   *
   * @param index index number of the signature to return
   * @return signature
   * @deprecated will be removed in the future.
   */
  @Deprecated
  Signature getSignature(int index);

  /**
   * Return the count of Signature objects
   * @return count of Signature objects
   * @deprecated will be removed in the future.
   */
  @Deprecated
  int countSignatures();

  /**
   * Returns document type ASiC or DDOC
   *
   * @return document type
   * @deprecated will be removed in the future.
   */
  @Deprecated
  DocumentType getDocumentType();


  /**
   * Returns container version in case of DDOC. BDOC does not have a version and it returns null
   *
   * @return version
   * @deprecated will be removed in the future.
   */
  @Deprecated
  String getVersion();

  /**
   * Extends signature profile to SignatureProfile
   * *
   *
   * @param profile signature profile
   * @see SignatureProfile
   * @deprecated will be removed in the future.
   */
  @Deprecated
  void extendTo(SignatureProfile profile);

  /**
   * Extends signature profile to @see SignatureProfile
   *
   * @param profile signature profile
   * @deprecated will be removed in the future.
   */
  @Deprecated
  void setSignatureProfile(SignatureProfile profile);
}
