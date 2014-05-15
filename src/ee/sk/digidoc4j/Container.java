package ee.sk.digidoc4j;

import ee.sk.digidoc4j.exceptions.NotYetImplementedException;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.asic.ASiCEService;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Offers functionality for handling data files and signatures in a container
 * <p>
 * Container can contain several files and
 * all those files can be signed using signing certificates.
 * Container can only be signed if it contains data files.
 * Data files can be added and removed from a container only if the container is not signed.
 * To modify the data list of a signed container by adding or removing datafiles you must first
 * remove all the signatures
 * </p>
 */
public class Container {

  private CommonCertificateVerifier commonCertificateVerifier;
  private ASiCEService aSiCEService;
  Map<String, DataFile> dataFiles = new HashMap<String, DataFile>();

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
   * Create a new container object of type Container.
   */
  Container() {
//    AbstractSignatureTokenConnection token = new Pkcs12SignatureToken("test", "signout.p12");
//    DSSPrivateKeyEntry privateKey = token.getKeys().get(0);

    SignatureParameters parameters = new SignatureParameters();
    parameters.setSignatureLevel(SignatureLevel.ASiC_S_BASELINE_LT);
    parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
//    parameters.setPrivateKeyEntry(privateKey);
    commonCertificateVerifier = new CommonCertificateVerifier();

    aSiCEService = new ASiCEService(commonCertificateVerifier);
  }

  /**
   * Opens the container from a file.
   *
   * @param path container file name with path
   * @throws Exception is thrown when wasn't possible to find file
   */
  Container(final String path) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Adds a data file from the file system to the container.
   * <p>
   * Note:
   * Data files can be removed from a container only after all signatures have been removed
   * </p>
   *
   * @param path     data file to be added to the container
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   * @throws Exception thrown if the data file path is incorrect or a data file with same file name already exists.
   *                   Also, no data file can be added if the container already has one or more signatures
   */
  public final void addDataFile(final String path, final String mimeType) throws Exception {
    dataFiles.put(path, new DataFile(path, mimeType));
  }

  /**
   * Adds a data file from the input stream (i.e. the date file content can be read from the internal memory buffer)
   * <p>
   * Note:
   * Data files can be removed from a container only after all signatures have been removed
   * </p>
   *
   * @param is       input stream from where data is read
   * @param fileName data file name in the container
   * @param mimeType MIME type of the data file, for example 'text/plain' or 'application/msword'
   * @throws Exception thrown if the data file path is incorrect or a data file with same file name already exists.
   *                   Also, no data file can be added if the container already has one or more signatures
   */
  public final void addDataFile(final InputStream is, final String fileName, final String mimeType)
    throws Exception {
    throw new NotYetImplementedException();
  }


  /**
   * Adds a signature to the container.
   *
   * @param signature signature, which is added to the container
   * @throws Exception thrown if there are no data files in the container
   */
  public final void addRawSignature(final byte[] signature) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Adds signature from input stream to the container.
   *
   * @param signatureStream signature, which is added to the container.
   * @throws Exception thrown if there are no data files in the container
   */
  public final void addRawSignature(final InputStream signatureStream) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * @return list of all the data files in the container.
   */
  public final List<DataFile> getDataFiles() {
    return new ArrayList<DataFile>(dataFiles.values());
  }


  /**
   * Removes a data file from the container by data file name. If there is corresponding signature(s) then these
   * signatures will be deleted
   *
   * @param fileName name of the data file to be removed
   * @throws Exception thrown if the data file name is incorrect
   */
  public final void removeDataFile(final String fileName) throws Exception {
    dataFiles.remove(fileName);
  }

  /**
   * Removes a signature from the container by signature id.
   *
   * @param signatureId id of the signature to be removed
   * @throws Exception thrown if the signature id is incorrect
   */
  public final void removeSignature(final int signatureId) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Saves the container.
   *
   * @param path file name and path.
   * @throws Exception thrown if there was a failure saving the BDOC container.
   *                   For example if the added data file does not exist.
   */
  public final void save(final String path) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Signs all data files in the container with SignatureProfile.TS profile.
   *
   * @param signer signer implementation
   * @return signature
   * @throws Exception thrown if signing the container failed
   */
  public final Signature sign(final Signer signer) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Signs all data files in the container.
   *
   * @param signer  signer implementation
   * @param profile specifies the signature profile
   * @return signature
   * @throws Exception thrown if signing the container failed
   */
  public final Signature sign(final Signer signer, final SignatureProfile profile) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Signs all data files in the container.
   *
   * @param city                signature production place signed property (optional)
   * @param stateOrProvince     signature production place signed property (optional)
   * @param postalCode          signature production place signed property (optional)
   * @param countryName         signature production place signed property (optional)
   * @param signerRoles         the parameter may contain the signer's role and optionally the signer's resolution.
   *                            Note that only one signer role value (i.e. one <ClaimedRole> XML element)
   *                            should be used. If the signer role contains both role and resolution then they must be
   *                            separated with a slash mark, e.g. 'role / resolution'. Note that when setting the
   *                            resolution value then the role must also be specified.
   * @param pin                 PIN code for accessing the private key.
   * @param useFirstCertificate if set to 'true' the first signing certificate that is found from the certificate store
   *                            is chosen for signature creation and the certificate selection's dialog window is not
   *                            displayed to the user.
   * @return signature
   * @throws Exception thrown if signing the container failed
   */
  public final Signature sign(final String city, final String stateOrProvince, final String postalCode,
                              final String countryName, final List<String> signerRoles, final String pin,
                              final boolean useFirstCertificate) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * @return list of all signatures in the container
   * @throws NotYetImplementedException if method is not implemented
   */
  public final List<Signature> getSignatures() throws NotYetImplementedException {
    throw new NotYetImplementedException();
  }
}






