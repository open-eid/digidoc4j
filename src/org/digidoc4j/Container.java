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

import eu.europa.ec.markt.dss.signature.MimeType;
import org.apache.commons.io.IOUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.BDocContainer;
import org.digidoc4j.impl.DDocContainer;
import org.digidoc4j.utils.Helper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.digidoc4j.Container.DocumentType.BDOC;

/**
 * Offers functionality for handling data files and signatures in a container.
 * <p>
 * A container can contain several files and all those files can be signed using signing certificates.
 * A container can only be signed if it contains data files.
 * </p><p>
 * Data files can be added and removed from a container only if the container is not signed.
 * To modify the data list of a signed container by adding or removing datafiles you must first
 * remove all the signatures.
 * </p><p>
 * Example of creating and signing a container:</p><p>
 * PKCS12_SIGNER = new PKCS12Signer("my_cert.p12", "password".toCharArray());<br>
 * Container container = Container.create();<br>
 * container.addDataFile("test.txt", "text/plain");<br>
 * container.sign(PKCS12_SIGNER);<br>
 * container.save("test.bdoc");
 * </p><p>
 * Optionally you can specify certain settings and behavior using the SignatureParameters settings.<br>
 * Example of creating and signing a container with specific signature parameters:</p><p>
 * PKCS12_SIGNER = new PKCS12Signer("my_cert.p12", "password".toCharArray());<br>
 * Container container = Container.create();<br>
 * container.addDataFile("test.txt", "text/plain");<br>
 * SignatureParameters signatureParameters = new SignatureParameters();<br>
 * signatureParameters.setSignatureId("S0");<br>
 * container.setSignatureParameters(signatureParameters);<br>
 * container.sign(PKCS12_SIGNER);<br>
 * container.save("test.bdoc");
 * </p><p>
 * Example of performing a 2 step signing</p><p>
 * Container container = Container.create();<br>
 * container.addDataFile("test.txt", "text/plain");<br>
 * SignedInfo signedInfo = container.prepareSigning(signerCertificate);<br>
 * byte[] signature = getExternalSignature();<br>
 * container.signRaw(signature);<br>
 * container.save("test.bdoc");
 * </p>
 *
 * @see SignatureParameters
 */
public abstract class Container implements Serializable {
  private static final Logger logger = LoggerFactory.getLogger(Container.class);

  /**
   * Create a BDOC container.
   *
   * @return new BDOC Container
   */
  public static Container create() {
    logger.debug("");
    return create(BDOC);
  }

  /**
   * Create a container of the specified type.
   *
   * @param documentType Type of container to create
   * @return new container of the specified format
   */
  public static Container create(DocumentType documentType) {
    logger.debug("");
    if (documentType == BDOC)
      return new BDocContainer();
    return new DDocContainer();
  }

  /**
   * Create a container of specified type and with specified configuration
   *
   * @param documentType  Type of container to create
   * @param configuration Configuration to be used
   * @return new container of specified type
   */
  public static Container create(DocumentType documentType, Configuration configuration) {
    logger.debug("");
    if (documentType == BDOC)
      return new BDocContainer(configuration);
    return new DDocContainer(configuration);
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
        container = new DDocContainer(path, configuration);
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
    logger.debug("");
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

  public static Container open(InputStream stream, Configuration configuration) {
    logger.debug("");
    BufferedInputStream bufferedInputStream = new BufferedInputStream(stream);

    try {
        if (Helper.isZipFile(bufferedInputStream))
            return new BDocContainer(bufferedInputStream, true, configuration);
        return new DDocContainer(bufferedInputStream, configuration);
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
   * Creates BDOC container with given configuration
   *
   * @param configuration configuration used for container creation
   * @return BDOC container
   */
  public static Container create(Configuration configuration) {
    logger.debug("");
    return create(BDOC, configuration);
  }

  /**
   * Prepare signature.
   * After preparing the signature the container will have to be signed as well
   *
   * @param signerCert X509 Certificate to be used for preparing the signature
   * @return Signed info
   */
  public abstract SignedInfo prepareSigning(X509Certificate signerCert);

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
    DDOC;

    @Override
    public String toString() {
      logger.debug("");
      if (this == BDOC)
        return MimeType.ASICE.getMimeTypeString();
      return super.toString();
    }
  }

  /**
   * Signature profile format.
   */
  public enum SignatureProfile {
    /**
     * Time-mark, similar to LT.
     */
    LT_TM,
    /**
     * Time-stamp and OCSP confirmation
     */
    LT,
    /**
     * Archive timestamp, same as XAdES LTA (Long Term Archive time-stamp)
     */
    LTA,
    /**
     * no profile
     */
    B_BES
    //TODO: ADD later B_EPES, LTA_TM
  }

  /**
   * Return signature profile
   */
  public abstract String getSignatureProfile();

  /**
   * Set signature parameters
   *
   * @param signatureParameters Signature parameters. These are  related to the signing location and signer roles
   */
  public abstract void setSignatureParameters(SignatureParameters signatureParameters);

  /**
   * Get digest algorithm
   *
   * @return Digest algorithm
   */
  public abstract DigestAlgorithm getDigestAlgorithm();

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
   * Saves the container to the java.io.OutputStream.
   *
   * @param out output stream.
   * @see java.io.OutputStream
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
   * @param rawSignature raw signature
   * @return signature
   */
  public abstract Signature signRaw(byte[] rawSignature);

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
   * Validate container
   *
   * @return validation result
   */
  public abstract ValidationResult validate();

  /**
   * Returns container version in case of DDOC. BDOC does not have a version and it returns null
   *
   * @return version
   */
  public abstract String getVersion();

  /**
   * Extends signature profile to SignatureProfile
   * *
   *
   * @param profile signature profile
   * @see SignatureProfile
   */
  public abstract void extendTo(SignatureProfile profile);

  /**
   * Extends signature profile to @see SignatureProfile
   *
   * @param profile signature profile
   */
  public abstract void setSignatureProfile(SignatureProfile profile);
}
