package org.digidoc4j;

import eu.europa.ec.markt.dss.parameter.BLevelParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.asic.ASiCEService;
import eu.europa.ec.markt.dss.signature.token.AbstractSignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.Pkcs12SignatureToken;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.asic.ASiCXMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.https.CommonsDataLoader;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;
import eu.europa.ec.markt.dss.validation102853.tsp.OnlineTSPSource;
import prototype.MockServiceInfo;
import prototype.SKOnlineOCSPSource;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.digidoc4j.api.DataFile;
import org.digidoc4j.api.Signature;
import org.digidoc4j.api.Signer;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.api.exceptions.NotYetImplementedException;

import static eu.europa.ec.markt.dss.parameter.BLevelParameters.SignerLocation;
import static org.apache.commons.lang.StringUtils.isEmpty;

/**
 * Experimental code to implement ASiC-S container. There is lot's of duplication with BDocContainer. When experimenting is finished duplication is removed
 */
public class ASiCSContainer implements ContainerInterface {

  private CommonCertificateVerifier commonCertificateVerifier;
  private ASiCEService aSiCEService;
  final private Map<String, DataFile> dataFiles = new HashMap<String, DataFile>();
  private SignatureParameters signatureParameters;
  private DSSDocument signedDocument;
  eu.europa.ec.markt.dss.DigestAlgorithm digestAlgorithm = eu.europa.ec.markt.dss.DigestAlgorithm.SHA256;

  /**
   * Create a new container object of ASIC_E type Container.
   */
  public ASiCSContainer() {
    signatureParameters = new SignatureParameters();
    signatureParameters.setSignatureLevel(SignatureLevel.ASiC_E_BASELINE_B);
    signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    commonCertificateVerifier = new CommonCertificateVerifier();

    aSiCEService = new ASiCEService(commonCertificateVerifier);
  }

  /**
   * Opens the container from a file.
   *
   * @param path container file name with path
   */
  public ASiCSContainer(String path) {
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
  public void save(String path) {
    documentMustBeInitializedCheck();
    signedDocument.save(path);
  }

  private void documentMustBeInitializedCheck() {
    if (signedDocument == null)
      throw new NotYetImplementedException();
  }

  @Override
  public Signature sign(Signer signer) {
    addSignerInformation(signer);
    commonCertificateVerifier.setTrustedCertSource(getTSL());
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

  private TrustedListsCertificateSource getTSL() {
    final String lotlUrl = "file:trusted-test-tsl.xml";
    TrustedListsCertificateSource tslCertificateSource = new TrustedListsCertificateSource();
    tslCertificateSource.setDataLoader(new CommonsDataLoader());
    tslCertificateSource.setLotlUrl(lotlUrl);
    tslCertificateSource.setCheckSignature(false);
    tslCertificateSource.init();
    return tslCertificateSource;
  }

  private void addSignerInformation(Signer signer) {
    signatureParameters.setDigestAlgorithm(digestAlgorithm);
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

  public void verify() {
    documentMustBeInitializedCheck();

    AbstractSignatureTokenConnection token = new Pkcs12SignatureToken("test", "signout.p12");
    DSSPrivateKeyEntry privateKey = token.getKeys().get(0);
    final X509Certificate[] certificateChain = privateKey.getCertificateChain();
    final X509Certificate trustedCertificate = certificateChain[0];

    SignedDocumentValidator validator = ASiCXMLDocumentValidator.fromDocument(signedDocument);

    CommonCertificateVerifier verifier = new CommonCertificateVerifier();

    SKOnlineOCSPSource onlineOCSPSource = new SKOnlineOCSPSource();
    verifier.setOcspSource(onlineOCSPSource);

    TrustedListsCertificateSource trustedCertSource = getTSL();
    ServiceInfo mockServiceInfo = new MockServiceInfo();

    trustedCertSource.addCertificate(trustedCertificate, mockServiceInfo);

    verifier.setTrustedCertSource(trustedCertSource);
    validator.setCertificateVerifier(verifier);
    validator.validateDocument();
    SimpleReport simpleReport = validator.getSimpleReport();

    System.out.println(simpleReport);
  }

  private DataFile getFirstDataFile() {
    return (DataFile)dataFiles.values().toArray()[0];
  }

  @Override
  public List<Signature> getSignatures() {
    throw new NotYetImplementedException();
  }

  @Override
  public DocumentType getDocumentType() {
    return DocumentType.ASIC_E;
  }

  @Override public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    this.digestAlgorithm = eu.europa.ec.markt.dss.DigestAlgorithm.forName(digestAlgorithm.name(), eu.europa.ec.markt.dss.DigestAlgorithm.SHA256);
  }
}






