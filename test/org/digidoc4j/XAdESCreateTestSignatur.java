package org.digidoc4j;

import static org.digidoc4j.ContainerBuilder.DDOC_CONTAINER_TYPE;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.impl.bdoc.asic.DetachedContentCreator;
import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.BLevelParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.Policy;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.SignerLocation;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.client.crl.OnlineCRLSource;
import eu.europa.esig.dss.client.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.client.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import eu.europa.esig.dss.token.AbstractSignatureTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class XAdESCreateTestSignatur {

  protected AbstractSignatureTokenConnection signatureTokenConnection = null;
  protected DSSPrivateKeyEntry keyEntry = null;

  @Before
  public void setUp(){

  }

  @Test
  public void createBLineSignature() throws KeyStoreException, IOException {

    String privateKeyPath = "C:/DigiDoc4j/TestData/private-key.p12";
    char[] password = "test".toCharArray();

    try {
      signatureTokenConnection = new Pkcs12SignatureToken(privateKeyPath, String.valueOf(password));
    } catch (IOException e) {
      e.printStackTrace();
    }
    keyEntry = signatureTokenConnection.getKeys().get(0);
    CertificateToken signingCertificate = new CertificateToken(keyEntry.getCertificate().getCertificate());

    XAdESSignatureParameters parameters = new XAdESSignatureParameters();
    parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
    parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
    parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
    parameters.setSigningCertificate(signingCertificate);

    CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
    XAdESService service = new XAdESService(commonCertificateVerifier);

    DSSDocument toSignDocument = new FileDocument(new File(
        "testFiles/helper-files/test.txt"));

    ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

    SignatureValue signatureValue = signatureTokenConnection.sign(dataToSign, DigestAlgorithm.SHA256, keyEntry);

    DSSDocument signedDocument = service.signDocument(toSignDocument, parameters,
        signatureValue);
    OutputStream stream =  new FileOutputStream("C:/DigiDoc4j/TestData/128/XAdES_BASELINE_B.xml");
    signedDocument.writeTo(stream);

  }

  @Test
  public void openSignature() throws IOException {
    Container container = ContainerBuilder.
        aContainer(DDOC_CONTAINER_TYPE).
        withDataFile("testFiles/helper-files/test.txt", "text/plain").
        build();

    byte[] signatureBytes = FileUtils.readFileToByteArray(new File("C:/DigiDoc4j/TestData/128/XAdES_BASELINE_LT.xml"));

    Signature signature = SignatureBuilder.
        aSignature(container).
        openAdESSignature(signatureBytes);

    ValidationResult validationResult = container.validate();

  }

  @Test
  public void createXAdESBaseline_LTSiganture() throws KeyStoreException, FileNotFoundException {

    String privateKeyPath = "C:/DigiDoc4j/TestData/128/user_one.p12";
    //String privateKeyPath = "C:/DigiDoc4j/TestData/128/ec-digiid.p12";
   // char[] password = "test".toCharArray();
    char[] password = "user_one".toCharArray();
    //char[] password = "user_one".toCharArray();
    //char[] password ="inno".toCharArray();

    try {
      signatureTokenConnection = new Pkcs12SignatureToken(privateKeyPath, String.valueOf(password));
    } catch (IOException e) {
      e.printStackTrace();
    }
    keyEntry = signatureTokenConnection.getKeys().get(0);
    CertificateToken signingCertificate = new CertificateToken(keyEntry.getCertificate().getCertificate());

    XAdESSignatureParameters parameters = new XAdESSignatureParameters();
    parameters.clearCertificateChain();
    parameters.bLevel().setSigningDate(new Date());
    parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
    parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
    parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
    parameters.setSigningCertificateDigestMethod(DigestAlgorithm.SHA256);
    parameters.setEn319132(false);
    parameters.setSigningCertificate(signingCertificate);

    BLevelParameters bLevelParameters = parameters.bLevel();
    String signaturePolicyId = "http://www.example.com/policy.txt";
    DigestAlgorithm signaturePolicyHashAlgo = DigestAlgorithm.SHA256;
    String signaturePolicyDescription = "Policy text to digest";
    byte[] signaturePolicyDescriptionBytes = signaturePolicyDescription.getBytes();
    byte[] digestedBytes = DSSUtils.digest(signaturePolicyHashAlgo,
        signaturePolicyDescriptionBytes);

    Policy policy = new Policy();
    policy.setId(signaturePolicyId);
    policy.setDigestAlgorithm(signaturePolicyHashAlgo);
    policy.setDigestValue(digestedBytes);
    bLevelParameters.setSignaturePolicy(policy);

    SignerLocation signerLocation = new SignerLocation();
    signerLocation.setCountry("BE");
    signerLocation.setStateOrProvince("Luxembourg");
    signerLocation.setPostalCode("1234");
    signerLocation.setLocality("SimCity");
    bLevelParameters.setSignerLocation(signerLocation);

    CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
    CommonsDataLoader commonsHttpDataLoader = new CommonsDataLoader();

    KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource
        (new File("C:/DigiDoc4j/TestData/128/private-key.p12"), "PKCS12",
            "test");

    TrustedListsCertificateSource tslCertificateSource = new
        TrustedListsCertificateSource();
    TSLRepository tslRepository = new TSLRepository();
    tslRepository.setTrustedListsCertificateSource(tslCertificateSource);
    TSLValidationJob job = new TSLValidationJob();
    job.setDataLoader(commonsHttpDataLoader);
    job.setDssKeyStore(keyStoreCertificateSource);
//    job.setLotlUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml");
//    job.setLotlCode("EU");
    job.setLotlUrl("https://open-eid.github.io/test-TL/tl-mp-test-EE.xml");
    job.setLotlCode("EU");
    job.setRepository(tslRepository);
    job.refresh();

    commonCertificateVerifier.setTrustedCertSource(tslCertificateSource);

    OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
    onlineCRLSource.setDataLoader(commonsHttpDataLoader);
    commonCertificateVerifier.setCrlSource(onlineCRLSource);

    OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
    onlineOCSPSource.setDataLoader(commonsHttpDataLoader);
    commonCertificateVerifier.setOcspSource(onlineOCSPSource);

    // Create XAdES service for signature
    XAdESService service = new XAdESService(commonCertificateVerifier);

    // Set the Timestamp source
    String tspServer = "http://tsa.belgium.be/connect";
//    String tspServer = "http://tsa.sk.ee";
//    String tspServer = "http://demo.sk.ee/tsa";
    OnlineTSPSource onlineTSPSource = new OnlineTSPSource(tspServer);

    service.setTspSource(onlineTSPSource);

  //  DSSDocument toSignDocument = new FileDocument(new File("testFiles/helper-files/test.xml"));

    String path = "testFiles/helper-files/test.txt";
    String mimeType = "text/plain";

    DataFile dataFile = new DataFile(path, mimeType);

    List<DataFile> dataFiles = new ArrayList<>();
    dataFiles.add(dataFile);

    DetachedContentCreator detachedContentCreator = new DetachedContentCreator().populate(dataFiles);
    List<DSSDocument> toSignDocument = detachedContentCreator.getDetachedContentList();

    ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
    SignatureValue signatureValue = signatureTokenConnection.sign(dataToSign, DigestAlgorithm.SHA256, keyEntry);

    DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

    OutputStream stream =  new FileOutputStream("C:/DigiDoc4j/TestData/128/XAdES_BASELINE_LT.xml");
    try {
      signedDocument.writeTo(stream);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}
