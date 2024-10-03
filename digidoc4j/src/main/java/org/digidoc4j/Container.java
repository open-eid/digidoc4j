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

import eu.europa.esig.dss.enumerations.MimeTypeEnum;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.Collections;
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
 */
public interface Container extends Serializable {

  /**
   * Adds a data file from the file system to the container.
   * <p>
   * Note:
   * Data files can be added to a container only after all signatures have been removed.
   * </p>
   *
   * @param path     data file to be added to the container
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   * @return data file
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
   * @return data file
   */
  DataFile addDataFile(InputStream is, String fileName, String mimeType);

  /**
   * Adds a data file from the file system to the container.
   * <p>
   * Note:
   * Data files can be added to a container only after all signatures have been removed.
   * </p>
   *
   * @param file     data file to be added to the container
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   * @return data file
   */
  DataFile addDataFile(File file, String mimeType);

  /**
   * Adds the specified data file to the container.
   * <p>
   * Note:
   * Data files can be added to a container only after all signatures have been removed.
   * </p>
   *
   * @param dataFile data file to be added to the container
   */
  void addDataFile(DataFile dataFile);

  /**
   * Adds a new signature to the container.
   *
   * @param signature signature to be added.
   */
  void addSignature(Signature signature);

  /**
   * Adds a new timestamp token covering the contents of this container.
   *
   * @param timestamp timestamp to add to this container
   */
  void addTimestamp(Timestamp timestamp);

  /**
   * Returns the list of data files in the container.
   *
   * @return list of data files in the container
   */
  List<DataFile> getDataFiles();

  /**
   * Returns the type of the container.
   * The known container types are the following:<ul>
   * <li>{@value org.digidoc4j.Constant#ASICE_CONTAINER_TYPE}</li>
   * <li>{@value org.digidoc4j.Constant#ASICS_CONTAINER_TYPE}</li>
   * <li>{@value org.digidoc4j.Constant#BDOC_CONTAINER_TYPE}</li>
   * <li>{@value org.digidoc4j.Constant#DDOC_CONTAINER_TYPE}</li>
   * <li>{@value org.digidoc4j.Constant#PADES_CONTAINER_TYPE}</li>
   * </ul>
   * Custom implementations of this interface may return other custom types.
   *
   * @return type of the container
   */
  String getType();

  /**
   * Returns the list of signatures in the container.
   *
   * @return list of signatures in the container
   */
  List<Signature> getSignatures();

  /**
   * Returns the list of timestamp tokens that cover the contents of this container.
   *
   * @return list of timestamp tokens in this container
   */
  default List<Timestamp> getTimestamps() {
    return Collections.emptyList();
  }

  /**
   * Removes the data file from the container.
   * <p>
   * Note:
   * Data files can be removed from a container only after all signatures have been removed.
   * </p>
   * @param file data file to be removed from the container.
   */
  void removeDataFile(DataFile file);

  /**
   * Removes the signature from the container
   * @param signature signature to be removed.
   */
  void removeSignature(Signature signature);

  /**
   * Removes the specified timestamp token from this container.
   * <p>
   * Note:
   * A timestamp token can be removed from a container only if the container does not contain any other timestamp tokens
   * that cover the timestamp token to be removed.
   * </p>
   * @param timestamp timestamp token to remove from this container
   */
  void removeTimestamp(Timestamp timestamp);

  /**
   * Extends profile of all signatures to SignatureProfile
   *
   * @param profile signature profile
   * @see SignatureProfile
   */
  void extendSignatureProfile(SignatureProfile profile);

  /**
   * Extends profile of selected signatures to SignatureProfile
   *
   * @param profile signature profile
   * @param signaturesToExtend signatures selected for extension
   * @see SignatureProfile
   */
  void extendSignatureProfile(SignatureProfile profile, List<Signature> signaturesToExtend);

  /**
   * Saves the container to the specified location.
   *
   * @param filePath file name and path.
   */
  File saveAsFile(String filePath);

  /**
   * Saves the container as a stream.
   *
   * @return stream of the container.
   */
  InputStream saveAsStream();

  /**
   * Saves the container to the java.io.OutputStream.
   *
   * @param out output stream.
   * @see java.io.OutputStream
   */
  void save(OutputStream out);

  /**
   * Validate container
   *
   * @return validation result
   */
  ContainerValidationResult validate();

  /**
   * Adds timestamp token
   *
   * @param timeStampToken timestamp token
   *
   * @deprecated Deprecated for removal. Use {@link #addTimestamp(Timestamp)} instead.
   */
  @Deprecated
  void setTimeStampToken(DataFile timeStampToken);

  /**
   * Returns timestamp token
   *
   * @return TimestampToken
   * @deprecated Deprecated for removal. Use {@link #getTimestamps()} instead.
   */
  @Deprecated
  DataFile getTimeStampToken();

  /**
   * Gets Configuration
   * @return Configuration
   */
  Configuration getConfiguration();

  /**
   * Document types
   */
  enum DocumentType {
    /**
     * BDOC 2.1 container with mime-type "application/vnd.etsi.asic-e+zip"
     */
    BDOC,
    /**
     * DIGIDOC-XML 1.3 container
     */
    DDOC,
    /**
     * ASiCS container with mime-type "application/vnd.etsi.asic-s+zip"
     */
    ASICS,
    /**
     * ASiCE container with mime-type "application/vnd.etsi.asic-e+zip"
     */
    ASICE,
    /**
     * PADES container
     */
    PADES;

    @Override
    public String toString() {
      if (this == BDOC || this == ASICE)
        return MimeTypeEnum.ASICE.getMimeTypeString();
      if (this == ASICS)
        return MimeTypeEnum.ASICS.getMimeTypeString();
      return super.toString();
    }
  }

}
