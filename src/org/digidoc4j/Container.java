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
public class Container implements ContainerInterface {

  private ContainerInterface containerImplementation;

  /**
   * Creates Container specified by DocumentType
   *
   * @param documentType container type
   */
  public Container(DocumentType documentType) {
    if (documentType == DocumentType.ASIC)
      containerImplementation = new BDocContainer();
    else
      containerImplementation = new DDocContainer();
  }

  /**
   * Create a new container object of ASIC type Container.
   */
  public Container() {
    containerImplementation = new BDocContainer();
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
  public void addDataFile(String path, String mimeType) throws Exception {
    containerImplementation.addDataFile(path, mimeType);
  }

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
   * @throws Exception thrown if the data file path is incorrect or a data file with same file name already exists.
   *                   Also, no data file can be added if the container already has one or more signatures
   */
  public void addDataFile(InputStream is, String fileName, String mimeType)
    throws Exception {
    containerImplementation.addDataFile(is, fileName, mimeType);
  }


  /**
   * Adds a signature to the container.
   *
   * @param signature signature to be added to the container
   * @throws Exception thrown if there are no data files in the container
   */
  public void addRawSignature(byte[] signature) throws Exception {
    containerImplementation.addRawSignature(signature);
  }

  /**
   * Adds signature from the input stream to the container.
   *
   * @param signatureStream signature to be added to the container
   * @throws Exception thrown if there are no data files in the container
   */
  public void addRawSignature(InputStream signatureStream) throws Exception {
    containerImplementation.addRawSignature(signatureStream);
  }

  /**
   * Returns all data files in the container.
   *
   * @return list of all the data files in the container.
   */
  public List<DataFile> getDataFiles() {
    return containerImplementation.getDataFiles();
  }


  /**
   * Removes a data file from the container by data file name. Any corresponding signatures will be deleted.
   *
   * @param fileName name of the data file to be removed
   * @throws Exception thrown if the data file name is incorrect
   */
  public void removeDataFile(String fileName) throws Exception {
    containerImplementation.removeDataFile(fileName);
  }

  /**
   * Removes the signature with the given signature id from the container.
   *
   * @param signatureId id of the signature to be removed
   * @throws Exception thrown if the signature id is incorrect
   */
  public void removeSignature(int signatureId) throws Exception {
    containerImplementation.removeSignature(signatureId);
  }

  /**
   * Saves the container to the specified location.
   *
   * @param path file name and path.
   * @throws DigiDoc4JException thrown if there was a failure saving the BDOC container.
   *                            For example if the added data file does not exist.
   */
  public void save(String path) throws DigiDoc4JException {
    containerImplementation.save(path);
  }

  /**
   * Signs all data files in the container.
   *
   * @param signer signer implementation
   * @return signature
   * @throws Exception thrown if signing the container failed
   */
  public Signature sign(Signer signer) throws Exception {
    return containerImplementation.sign(signer);
  }

  /**
   * Returns a list of all signatures in the container.
   *
   * @return list of all signatures
   */
  public List<Signature> getSignatures() {
    return containerImplementation.getSignatures();
  }
}






