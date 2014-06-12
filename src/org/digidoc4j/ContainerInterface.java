package org.digidoc4j;

import java.io.InputStream;
import java.util.List;

import org.digidoc4j.exceptions.DigiDoc4JException;

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
    ASIC,
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
    TS;
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
   * @throws Exception thrown if the data file path is incorrect or a data file with the same filename already exists.
   *                   Also, no data file can be added if the container already has one or more signatures.
   */
  void addDataFile(String path, String mimeType) throws Exception;

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
   * @throws Exception thrown if there are no data files in the container
   */
  void addRawSignature(byte[] signature) throws Exception;

  /**
   * Adds signature from the input stream to the container.
   *
   * @param signatureStream signature to be added to the container
   * @throws Exception thrown if there are no data files in the container
   */
  void addRawSignature(InputStream signatureStream) throws Exception;

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
   * @throws Exception thrown if the data file name is incorrect
   */
  void removeDataFile(String fileName) throws Exception;

  /**
   * Removes the signature with the given signature id from the container.
   *
   * @param signatureId id of the signature to be removed
   * @throws Exception thrown if the signature id is incorrect
   */
  void removeSignature(int signatureId) throws Exception;

  /**
   * Saves the container to the specified location.
   *
   * @param path file name and path.
   * @throws org.digidoc4j.exceptions.DigiDoc4JException
   *          thrown if there was a failure saving the BDOC container.
   *          For example if the added data file does not exist.
   */
  void save(String path) throws DigiDoc4JException;

  /**
   * Signs all data files in the container.
   *
   * @param signer signer implementation
   * @return signature
   * @throws Exception thrown if signing the container failed
   */
  Signature sign(Signer signer) throws Exception;


  /**
   * Returns a list of all signatures in the container.
   *
   * @return list of all signatures
   */
  List<Signature> getSignatures();

  /**
   * Returns document type AISC or DDOC
   */

  DocumentType getDocumentType();
}






