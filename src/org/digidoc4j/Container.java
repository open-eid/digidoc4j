package org.digidoc4j;

import org.apache.commons.io.IOUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.BDocContainer;
import org.digidoc4j.impl.DDocContainer;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.List;

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
public abstract class Container {
  private static final Logger logger = LoggerFactory.getLogger(Container.class);

  /**
   * Create an ASIC_E container.
   *
   * @return new ASIC_E Container
   */
  public static Container create() {
    logger.debug("");
    return create(DocumentType.BDOC);
  }

  /**
   * Create a container of the specified type.
   *
   * @param documentType Type of container to create
   * @return new container of the specified format
   */
  public static Container create(DocumentType documentType) {
    logger.debug("");
    Container container;
    if (documentType == DocumentType.BDOC) {
      container = new BDocContainer();
    } else {
      container = new DDocContainer();
    }

    logger.info("Container with type " + container.getDocumentType() + " has been created");
    return container;
  }

  /**
   * Open container from a file
   *
   * @param path          file name and path.
   * @param configuration configuration settings
   * @return container new container of the specified format
   * @throws DigiDoc4JException when the file is not found or empty
   */
  public static Container open(String path, Configuration configuration) throws DigiDoc4JException {
    logger.debug("Path: " + path);
    Container container;
    try {
      if (Helper.isZipFile(new File(path))) {
        configuration.loadConfiguration("digidoc4j.yaml");
        container = new BDocContainer(path, configuration);
      } else {
        container = new DDocContainer(path);
      }
      return container;
    } catch (EOFException eof) {
      String msg = "File is not valid.";
      logger.error(msg);
      throw new DigiDoc4JException(msg);
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    }
  }

  /**
   * Open container from a file
   *
   * @param path file name and path.
   * @return container
   * @throws DigiDoc4JException when the file is not found or empty
   */
  public static Container open(String path) throws DigiDoc4JException {
    return open(path, new Configuration());
  }

  /**
   * Open container from a stream
   *
   * @param stream                      input stream
   * @param actAsBigFilesSupportEnabled acts as configuration parameter
   * @return container
   * @see Configuration#isBigFilesSupportEnabled() returns true used for BDOC
   */
  public static Container open(InputStream stream, boolean actAsBigFilesSupportEnabled) {
    logger.debug("");
    BufferedInputStream bufferedInputStream = new BufferedInputStream(stream);

    try {
      if (Helper.isZipFile(bufferedInputStream))
        return new BDocContainer(bufferedInputStream, actAsBigFilesSupportEnabled);
      return new DDocContainer(bufferedInputStream);
    } catch (IOException e) {
      logger.error(e.getMessage());
      throw new DigiDoc4JException(e);
    } finally {
      IOUtils.closeQuietly(bufferedInputStream);
    }
  }

  protected Container() {
    logger.debug("");
  }

  /**
   * Document types
   */
  public enum DocumentType {
    /**
     * BDOC 2.1 container with mime-type "application/vnd.etsi.asic-e+zip"
     */
    BDOC,
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
    TS,
    /**
     * no profile
     */
    NONE
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
  public abstract void addDataFile(String path, String mimeType);

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
  public abstract void addDataFile(InputStream is, String fileName, String mimeType);

  /**
   * Adds a signature to the container.
   *
   * @param signature signature to be added to the container
   */
  public abstract void addRawSignature(byte[] signature);

  /**
   * Adds signature from the input stream to the container.
   * For BDOC it throws a NotYetImplementedException().
   *
   * @param signatureStream signature to be added to the container
   */
  public abstract void addRawSignature(InputStream signatureStream);

  /**
   * Returns all data files in the container.
   *
   * @return list of all the data files in the container.
   */
  public abstract List<DataFile> getDataFiles();

  /**
   * Returns a data file
   *
   * @param index index number of the data file to return
   * @return data file
   */
  public abstract DataFile getDataFile(int index);

  /**
   * Removes a data file from the container by data file name. Any corresponding signatures will be deleted.
   *
   * @param fileName name of the data file to be removed
   */
  public abstract void removeDataFile(String fileName);

  /**
   * Removes the signature with the given signature id from the container.
   *
   * @param signatureId id of the signature to be removed
   */
  public abstract void removeSignature(int signatureId);

  /**
   * Saves the container to the specified location.
   *
   * @param path file name and path.
   */
  public abstract void save(String path);

  /**
   * Saves the container to the @see java.io.OutputStream.
   *
   * @param out output stream.
   */
  public abstract void save(OutputStream out);

  /**
   * Signs all data files in the container.
   *
   * @param signer signer implementation
   * @return signature
   */
  public abstract Signature sign(Signer signer);

  /**
   * Signs all data files in the container.
   *
   * @param signer signer implementation
   * @param signatureId sets signature id
   * @return signature
   */
  public abstract Signature sign(Signer signer, String signatureId);

  /**
   * Sets configuration for container.
   * For a DDOC Container it throws a NotYetImplementedException.
   *
   * @param conf configuration
   */
  public abstract void setConfiguration(Configuration conf);

  /**
   * Returns a list of all signatures in the container.
   *
   * @return list of all signatures
   */
  public abstract List<Signature> getSignatures();

  /**
   * Return signature
   *
   * @param index index number of the signature to return
   * @return signature
   */
  public abstract Signature getSignature(int index);

  /**
   * Returns document type ASiC or DDOC
   *
   * @return document type
   */
  public abstract DocumentType getDocumentType();

  //--- differences with CPP library

  /**
   * Sets container digest type
   *
   * @param algorithm digest algorithm
   */
  public abstract void setDigestAlgorithm(DigestAlgorithm algorithm);

  /**
   * Validate container
   *
   * @return validation result
   */
  public abstract ValidationResult validate();

  /**
   * Signs all data files in the container. No OCSP confirmation is added
   *
   * @param signer signer implementation
   * @return signature
   */
  public abstract Signature signWithoutOCSP(Signer signer);

  /**
   * Signs all data files in the container. No OCSP confirmation is added
   *
   * @param signer      signer implementation
   * @param signatureId sets signature id
   * @return signature
   */
  public abstract Signature signWithoutOCSP(Signer signer, String signatureId);

  /**
   * Adds OCSP confirmation
   */
  public abstract void addConfirmation();

  /**
   * Returns container version in case of DDOC. BDOC does not have a version and it returns null
   *
   * @return version
   */
  public abstract String getVersion();
}






