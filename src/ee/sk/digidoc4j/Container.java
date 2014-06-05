package ee.sk.digidoc4j;

import ee.sk.digidoc4j.exceptions.NotYetImplementedException;
import ee.sk.utils.SKOnlineOCSPSource;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.asic.ASiCEService;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.https.CommonsDataLoader;
import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;
import eu.europa.ec.markt.dss.validation102853.tsp.OnlineTSPSource;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static eu.europa.ec.markt.dss.parameter.BLevelParameters.SignerLocation;
import static org.apache.commons.lang.StringUtils.isEmpty;

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
public class Container {

  private CommonCertificateVerifier commonCertificateVerifier;
  private ASiCEService aSiCEService;
  Map<String, DataFile> dataFiles = new HashMap<String, DataFile>();
  private SignatureParameters signatureParameters;
  private DSSDocument signedDocument;

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
  public Container() {
//    AbstractSignatureTokenConnection token = new Pkcs12SignatureToken("test", "signout.p12");
//    DSSPrivateKeyEntry privateKey = token.getKeys().get(0);

    signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureLevel(SignatureLevel.ASiC_S_BASELINE_LT);
    signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
    commonCertificateVerifier = new CommonCertificateVerifier();

    aSiCEService = new ASiCEService(commonCertificateVerifier);
  }

  /**
   * Opens the container from a file.
   *
   * @param path container file name with path
   * @throws Exception is thrown when the file was not found.
   */
  public Container(String path) throws Exception {
    throw new NotYetImplementedException();
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
    dataFiles.put(path, new DataFile(path, mimeType));
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
    throw new NotYetImplementedException();
  }


  /**
   * Adds a signature to the container.
   *
   * @param signature signature to be added to the container
   * @throws Exception thrown if there are no data files in the container
   */
  public void addRawSignature(byte[] signature) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Adds signature from the input stream to the container.
   *
   * @param signatureStream signature to be added to the container
   * @throws Exception thrown if there are no data files in the container
   */
  public void addRawSignature(InputStream signatureStream) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Returns all data files in the container.
   *
   * @return list of all the data files in the container.
   */
  public List<DataFile> getDataFiles() {
    return new ArrayList<DataFile>(dataFiles.values());
  }


  /**
   * Removes a data file from the container by data file name. Any corresponding signatures will be deleted.
   *
   * @param fileName name of the data file to be removed
   * @throws Exception thrown if the data file name is incorrect
   */
  public void removeDataFile(String fileName) throws Exception {
    if (dataFiles.remove(fileName) == null) throw new FileNotFoundException();  //TODO which Exception to throw
  }

  /**
   * Removes the signature with the given signature id from the container.
   *
   * @param signatureId id of the signature to be removed
   * @throws Exception thrown if the signature id is incorrect
   */
  public void removeSignature(int signatureId) throws Exception {
    throw new NotYetImplementedException();
  }

  /**
   * Saves the container to the specified location.
   *
   * @param path file name and path.
   * @throws Exception thrown if there was a failure saving the BDOC container.
   *                   For example if the added data file does not exist.
   */
  public void save(String path) throws Exception {
    signedDocument.save(path);                                                   //TODO which exception and when
  }

  /**
   * Signs all data files in the container.
   *
   * @param signer signer implementation
   * @return signature
   * @throws Exception thrown if signing the container failed
   */
  public Signature sign(Signer signer) throws Exception {
    addSignerInformation(signer);
    setTSL();
    commonCertificateVerifier.setOcspSource(new SKOnlineOCSPSource());

    aSiCEService = new ASiCEService(commonCertificateVerifier);
    aSiCEService.setTspSource(new OnlineTSPSource("http://tsa01.quovadisglobal.com/TSS/HttpTspServer"));
    signatureParameters.setSigningCertificate(signer.getCertificate().getX509Certificate());

    //TODO throw error if no file exists
    DSSDocument toSignDocument = new FileDocument(getFirstDataFile().getFileName());

    byte[] dataToSign = aSiCEService.getDataToSign(toSignDocument, signatureParameters);
    byte[] signatureValue = signer.sign(signatureParameters.getDigestAlgorithm().getXmlId(), dataToSign);
    signedDocument = aSiCEService.signDocument(toSignDocument, signatureParameters, signatureValue);

    return (new Signature(signatureValue, signatureParameters));
  }

  private void setTSL() {
    final String lotlUrl = "file:trusted-test-tsl.xml";
    TrustedListsCertificateSource tslCertificateSource = new TrustedListsCertificateSource();
    tslCertificateSource.setDataLoader(new CommonsDataLoader());
    tslCertificateSource.setLotlUrl(lotlUrl);
    tslCertificateSource.setCheckSignature(false);
    tslCertificateSource.init();
    commonCertificateVerifier.setTrustedCertSource(tslCertificateSource);
  }

  private void addSignerInformation(Signer signer) {
    BLevelParameters bLevelParameters = signatureParameters.bLevel();
    SignerLocation signerLocation = new SignerLocation();

    if (!isEmpty(signer.getCity())) signerLocation.setCity(signer.getCity());
    if (!isEmpty(signer.getStateOrProvince()))
      signerLocation.setStateOrProvince(signer.getStateOrProvince());
    if (!isEmpty(signer.getPostalCode())) signerLocation.setPostalCode(signer.getPostalCode());
    if (!isEmpty(signer.getCountry())) signerLocation.setCountry(signer.getCountry());
    bLevelParameters.setSignerLocation(signerLocation);
    for (String signerRole : signer.getSignerRoles()) {
      bLevelParameters.addClaimedSignerRole(signerRole);
    }
  }

  private DataFile getFirstDataFile() {
    return (DataFile) dataFiles.values().toArray()[0];
  }

//  /**
//   * Signs all data files in the container.
//   *
//   * @param signer  signer implementation
//   * @param profile specifies the signature profile
//   * @return signature
//   * @throws Exception thrown if signing the container failed
//   */
//  public Signature sign(Signer signer, SignatureProfile profile) throws Exception {
//    throw new NotYetImplementedException();
//  }

//  /**
//   * Signs all data files in the container.
//   *
//   * @param city                production city of the signature (optional)
//   * @param stateOrProvince     production state or province of the signature (optional)
//   * @param postalCode          production postal code of the signature (optional)
//   * @param country         production country of the signature (optional)
//   * @param signerRole         the parameter may contain the signer’s role and optionally the signer’s resolution
//   *                            Note that only one signer role value (i.e. one <ClaimedRole> XML element) should
//   *                            be used
//   *                            If the signer role contains both role and resolution then they must be separated
//   *                            with a slash mark, e.g. “role / resolution”
//   *                            Note that when setting the resolution value then role must also be specified
//   * @param pin                 PIN code for accessing the private key
//   * @param useFirstCertificate if set to “true” it will use the first signing certificate from the certificate store
//   *                            for signature creation and the certificate selection dialog window is not displayed
//   *                            to the user<p>
//   *                            if set to "false", the certificate selection's dialog window is displayed</p>
//   * @return signature
//   * @throws Exception thrown if signing the container failed
//   */
//  public Signature sign(String city, String stateOrProvince, String postalCode, String country,
//                        String signerRole, String pin, boolean useFirstCertificate) throws Exception {
//
//    throw new NotYetImplementedException();
//  }

  /**
   * Returns a list of all signatures in the container.
   *
   * @return list of all signatures
   * @throws NotYetImplementedException if method is not implemented
   */
  public List<Signature> getSignatures() throws NotYetImplementedException {
    throw new NotYetImplementedException();
  }
}






