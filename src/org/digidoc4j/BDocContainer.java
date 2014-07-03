package org.digidoc4j;

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
import org.digidoc4j.api.DataFile;
import org.digidoc4j.api.Signature;
import org.digidoc4j.api.Signer;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.NotYetImplementedException;
import prototype.SKOnlineOCSPSource;

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
public class BDocContainer implements ContainerInterface {

  private CommonCertificateVerifier commonCertificateVerifier;
  private ASiCEService aSiCEService;
  Map<String, DataFile> dataFiles = new HashMap<String, DataFile>();
  private SignatureParameters signatureParameters;
  private DSSDocument signedDocument;

  /**
   * Create a new container object of ASIC type Container.
   */
  public BDocContainer() {
    signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureLevel(SignatureLevel.ASiC_E_BASELINE_B);
    signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    signatureParameters.setDigestAlgorithm(eu.europa.ec.markt.dss.DigestAlgorithm.SHA256);
    commonCertificateVerifier = new CommonCertificateVerifier();

    aSiCEService = new ASiCEService(commonCertificateVerifier);
  }


  /**
   * Opens the container from a file.
   *
   * @param path container file name with path
   */
  public BDocContainer(String path) {
    signedDocument = new FileDocument(path);
  }

  @Override
  public void addDataFile(String path, String mimeType) {
    dataFiles.put(path, new DataFile(path, mimeType));
  }

  @Override
  public void addDataFile(InputStream is, String fileName, String mimeType) {
    throw new NotYetImplementedException();
  }

  @Override
  public void addRawSignature(byte[] signature) {
    throw new NotYetImplementedException();
  }

  @Override
  public void addRawSignature(InputStream signatureStream) {
    throw new NotYetImplementedException();
  }

  @Override
  public List<DataFile> getDataFiles() {
    return new ArrayList<DataFile>(dataFiles.values());
  }

  @Override
  public void removeDataFile(String fileName) {
    if (dataFiles.remove(fileName) == null) throw new DigiDoc4JException("File not found");
  }

  @Override
  public void removeSignature(int signatureId) {
    throw new NotYetImplementedException();
  }

  @Override
  public void save(String path) throws DigiDoc4JException {
    if (signedDocument == null)
      throw new NotYetImplementedException();
    signedDocument.save(path);
  }

  @Override
  public Signature sign(Signer signer) {
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

    return new Signature(signatureValue, signatureParameters);
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

  @Override
  public List<Signature> getSignatures() {
    throw new NotYetImplementedException();
  }

  @Override
  public DocumentType getDocumentType() {
    return DocumentType.ASIC_E;
  }

  @Override
  public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {

  }
}






