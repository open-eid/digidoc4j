package org.digidoc4j;

import java.io.InputStream;
import java.util.List;

import org.digidoc4j.api.DataFile;
import org.digidoc4j.api.Signature;
import org.digidoc4j.api.Signer;

/**
 * Offers functionality for handling data files and signatures in a container.
 * <p>
 * A container can contain several files and all those files can be signed using signing certificates.
 * A container can only be signed if it contains data files.
 * </p><p>
 * Data files can be added and removed from a container only if the container is not signed.
 * To modify the data list of a signed container by adding or removing datafiles you must first
 * remove all the signatures.
 * </p>
 */
public interface ContainerInterface {

  /**
   * Document types
   */
  public enum DocumentType {
    /**
     * BDOC 2.1 container with mime-type "application/vnd.etsi.asic-e+zip"
     */
    ASIC_E,
    /**
     * ASiC-S container with mime-type "application/vnd.etsi.asic-e+zip"
     */
    ASIC_S,
    /**
     * DIGIDOC-XML 1.3 container
     */
    DDOC
  }

  /**
   * Signature profile format.
   */
  public enum SignatureProfile {
    /**
     * Time-mark.
     */
    TM,
    /**
     * Time-stamp.
     */
    TS
  }

  /**
   * Digest algorithm
   */
  public enum DigestAlgorithm {
    SHA1,
    SHA224,
    SHA256,
    SHA512
  }

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
  void addDataFile(String path, String mimeType);

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
  void addDataFile(InputStream is, String fileName, String mimeType);


  /**
   * Adds a signature to the container.
   *
   * @param signature signature to be added to the container
   */
  void addRawSignature(byte[] signature);

  /**
   * Adds signature from the input stream to the container.
   *
   * @param signatureStream signature to be added to the container
   */
  void addRawSignature(InputStream signatureStream);

  /**
   * Returns all data files in the container.
   *
   * @return list of all the data files in the container.
   */
  List<DataFile> getDataFiles();


  /**
   * Removes a data file from the container by data file name. Any corresponding signatures will be deleted.
   *
   * @param fileName name of the data file to be removed
   */
  void removeDataFile(String fileName);

  /**
   * Removes the signature with the given signature id from the container.
   *
   * @param signatureId id of the signature to be removed
   */
  void removeSignature(int signatureId);

  /**
   * Saves the container to the specified location.
   *
   * @param path file name and path.
   */
  void save(String path);

  /**
   * Signs all data files in the container.
   *
   * @param signer signer implementation
   * @return signature
   */
  Signature sign(Signer signer);


  /**
   * Returns a list of all signatures in the container.
   *
   * @return list of all signatures
   */
  List<Signature> getSignatures();

  /**
   * Returns document type ASiC or DDOC
   *
   * @return document type
   */
  DocumentType getDocumentType();

  //--- differences with CPP library

  /**
   * Sets container digest type
   */
  void setDigestAlgorithm(DigestAlgorithm digestAlgorithm);
}






