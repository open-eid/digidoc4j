package ee.sk.digidoc4j;

import java.io.InputStream;
import java.util.List;

/**
 * Offers functionality for handling data files and signatures in a container
 * <p>
 * Container can contain several files and
 * all those files can be signed using signing certificates.
 * Container can only be signed if it contains data files.
 * Data files can be added and removed from a container only if the container is not signed.
 * To modify the data list of a signed container by adding or removing datafiles you must first remove all the signatures
 * </p>
 */
public class Container {

  /**
   * Binary encoding format
   */
  public enum DocumentType {
    /**
     * creates a new BDOC 2.1 container with mime-type 'application/vnd.etsi.asic-e+zip'
     */
    ASIC,
    /**
     * creates a new BDOC 1.0 container with mime-type 'application/vnd.bdoc-1.0'
     *
     * @deprecated Defaults to AsicType
     *             <p>Note: the functionality of creating new files in DigiDoc file format BDOC 1.0 is not supported</p>
     */
    BDOC;
  }

  /**
   * Signature profile format
   */
  public enum SignatureProfile {
    /**
     * time-mark
     */
    TM,
    /**
     * time-stamp
     */
    TS;
    //TMA //time-mark-archive
    //TSA //time-stamp-archive
  }

  /**
   * Create a new container object of type Container.ASIC
   */
  Container() {
  }

  /**
   * Create a new container object and specify the DigiDoc container type
   *
   * @param type digidoc type
   */
  Container(DocumentType type) {
  }

  /**
   * Opens the container from a file
   *
   * @param path
   * @throws Exception
   */
  Container(String path) throws Exception {
  }

  /**
   * Adds a data file from the file system to the container
   * <p>
   * Note:
   * Data files can be removed from a container only after all signatures have been removed
   * </p>
   *
   * @param path      data file to be added to the container
   * @param mediaType MIME type of the data file, for example 'text/plain' or 'application/msword'
   * @throws Exception thrown if the data file path is incorrect or a data file with same file name already exists. Also, no data file can be added if the container already has one or more signatures
   */
  public void addDataFile(String path, String mediaType) throws Exception {
  }

  /**
   * Adds a data file from the input stream (i.e. the date file content can be read from the internal memory buffer)
   * <p>
   * Note:
   * Data files can be removed from a container only after all signatures have been removed
   * </p>
   *
   * @param is        input stream from where data is read
   * @param fileName  data file name in the container
   * @param mediaType MIME type of the data file, for example 'text/plain' or 'application/msword'
   * @throws Exception thrown if the data file path is incorrect or a data file with same file name already exists. Also, no data file can be added if the container already has one or more signatures
   */
  public void addDataFile(InputStream is, String fileName, String mediaType) throws Exception {
  }


  /**
   * Adds a signature to the container
   *
   * @param signature signature, which is added to the container
   * @throws Exception thrown if there are no data files in the container
   */
  public void addRawSignature(byte[] signature) throws Exception {
  }

  /**
   * Adds signature from input stream to the container
   *
   * @param signatureStream signature, which is added to the container.
   * @throws Exception thrown if there are no data files in the container
   */
  public void addRawSignature(InputStream signatureStream) throws Exception {
  }

  /**
   * Returns a list of all the data files in the container
   */
  public List<DataFile> getDataFiles() {
    return null;
  }


  /**
   * Returns current data file format
   */
  String getMediaType() {
    return null;
  }

  /**
   * Removes a data file from the container by data file id. Data files can be removed from the container only after all signatures have been removed
   *
   * @param fileId id of the data file to be removed
   * @throws Exception thrown if the data file id is incorrect or there are one or more signatures
   */
  public void removeDataFile(int fileId) throws Exception {
  }

  /**
   * Removes a signature from the container by signature id
   *
   * @param signatureId id of the signature to be removed
   * @throws Exception thrown if the signature id is incorrect
   */
  public void removeSignature(int signatureId) throws Exception {
  }

  /**
   * Saves the container
   *
   * @param path
   * @throws Exception thrown if there was a failure saving the BDOC container. For example if the added data file does not exist
   */
  public void save(String path) throws Exception {
  }

  /**
   * Signs all data files in the container with SignatureProfile.TS profile
   *
   * @param signer signer implementation
   * @throws Exception thrown if signing the container failed
   */
  public Signature sign(Signer signer) throws Exception {
    return null;
  }

  /**
   * Signs all data files in the container
   *
   * @param signer  signer implementation
   * @param profile specifies the signature profile.
   * @throws Exception thrown if signing the container failed
   */
  public Signature sign(Signer signer, SignatureProfile profile) throws Exception {
    return null;
  }

  /**
   * Signs all data files in the container
   *
   * @param city                signature production place signed property (optional)
   * @param stateOrProvince     signature production place signed property (optional)
   * @param postalCode          signature production place signed property (optional)
   * @param countryName         signature production place signed property (optional)
   * @param signerRoles         the parameter may contain the signer's role and optionally the signer's resolution. Note that only one signer role value (i.e. one <ClaimedRole> XML element) should be used. If the signer role contains both role and resolution then they must be separated with a slash mark, e.g. 'role / resolution'. Note that when setting the resolution value then the role must also be specified
   * @param pin                 PIN code for accessing the private key
   * @param useFirstCertificate if set to 'true' the first signing certificate that is found from the certificate store is chosen for signature creation and the certificate selection's dialog window is not displayed to the user
   * @throws Exception thrown if signing the container failed
   */
  public Signature sign(String city, String stateOrProvince, String postalCode, String countryName, List<String> signerRoles, String pin, boolean useFirstCertificate) throws Exception {
    return null;
  }

  /**
   * Returns a list of all signatures in the container
   */
  public List<Signature> signatures() {
    return null;
  }

}






