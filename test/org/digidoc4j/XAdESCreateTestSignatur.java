package org.digidoc4j;

import static org.digidoc4j.ContainerBuilder.BDOC_CONTAINER_TYPE;
import static org.digidoc4j.ContainerBuilder.DDOC_CONTAINER_TYPE;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.impl.bdoc.SkDataLoader;
import org.digidoc4j.impl.bdoc.asic.DetachedContentCreator;
import org.digidoc4j.impl.bdoc.ocsp.BDocTSOcspSource;
import org.digidoc4j.impl.bdoc.xades.XadesSigningDssFacade;
import org.digidoc4j.testutils.TestSigningHelper;
import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.BLevelParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
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
  private XadesSigningDssFacade facade;
  private Configuration configuration;

  private String BDOC = "BDOC";
  private String DATA_FILE = "testFiles/helper-files/test.txt";
  private String BDOC_FILE = "C:/DigiDoc4j/TestData/128/twoSignatureErrorsContainer.bdoc";
  private String TEXT_PLAIN = "text/plain";
  private String SIGNATURE_1 = "C:/DigiDoc4j/TestData/128/signature1.xml";
  private String SIGNATUR_2 = "C:/DigiDoc4j/TestData/128/signature2.xml";
  private String BASELINE_LT_SIGNATURE = "C:/DigiDoc4j/TestData/128/XAdES_BASELINE_LT.xml";

  @Before
  public void setUp(){
    configuration = new Configuration(Configuration.Mode.TEST);
    facade = createSigningFacade();
  }

  private XadesSigningDssFacade createSigningFacade() {
    XadesSigningDssFacade facade = new XadesSigningDssFacade();
    facade.setCertificateSource(configuration.getTSL());
    facade.setOcspSource(createOcspSource());
    facade.setTspSource(createTSPSource());
    return facade;
  }

  private BDocTSOcspSource createOcspSource() {
    BDocTSOcspSource ocspSource = new BDocTSOcspSource(configuration);
    SkDataLoader dataLoader = SkDataLoader.createOcspDataLoader(configuration);
    dataLoader.setUserAgentSignatureProfile(SignatureProfile.LT);
    ocspSource.setDataLoader(dataLoader);
    return ocspSource;
  }

  private OnlineTSPSource createTSPSource() {
    SkDataLoader timestampDataLoader = SkDataLoader.createTimestampDataLoader(configuration);
    timestampDataLoader.setUserAgentSignatureProfile(SignatureProfile.LT);
    OnlineTSPSource tspSource = new OnlineTSPSource(configuration.getTspSource());
    tspSource.setDataLoader(timestampDataLoader);
    return tspSource;
  }

  @Test
  public void createXAdESBaseline_LTSiganture() throws KeyStoreException, FileNotFoundException {

    String privateKeyPath = "C:/DigiDoc4j/TestData/128/user_one.p12";
    String password = "user_one";
    String LOTL_URL = "https://open-eid.github.io/test-TL/tl-mp-test-EE.xml";
    //https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml

    // Set the Timestamp source
    String TSP_SERVER = "http://tsa.belgium.be/connect";
    // http://tsa.sk.ee
    // http://demo.sk.ee/tsa

    try {
      signatureTokenConnection = new Pkcs12SignatureToken(privateKeyPath, password);
    } catch (IOException e) {
      e.printStackTrace();
    }

    keyEntry = signatureTokenConnection.getKeys().get(0);
    CertificateToken signingCertificate = new CertificateToken(keyEntry.getCertificate().getCertificate());

    XAdESSignatureParameters parameters = new XAdESSignatureParameters();
    parameters.clearCertificateChain();
    parameters.bLevel().setSigningDate(new Date());
    parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
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
        (new File(privateKeyPath), "PKCS12",
            password);

    TrustedListsCertificateSource tslCertificateSource = new
        TrustedListsCertificateSource();
    TSLRepository tslRepository = new TSLRepository();
    tslRepository.setTrustedListsCertificateSource(tslCertificateSource);
    TSLValidationJob job = new TSLValidationJob();
    job.setDataLoader(commonsHttpDataLoader);
    job.setDssKeyStore(keyStoreCertificateSource);
    job.setLotlUrl(LOTL_URL);
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

    XAdESService service = new XAdESService(commonCertificateVerifier);

    OnlineTSPSource onlineTSPSource = new OnlineTSPSource(TSP_SERVER);

    service.setTspSource(onlineTSPSource);

    DataFile dataFile = new DataFile(DATA_FILE, TEXT_PLAIN);

    List<DataFile> dataFiles = new ArrayList<>();
    dataFiles.add(dataFile);

    DetachedContentCreator detachedContentCreator = new DetachedContentCreator().populate(dataFiles);
    List<DSSDocument> toSignDocument = detachedContentCreator.getDetachedContentList();

    ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
    SignatureValue signatureValue = signatureTokenConnection.sign(dataToSign, DigestAlgorithm.SHA256, keyEntry);

    DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

    OutputStream stream =  new FileOutputStream(BASELINE_LT_SIGNATURE);
    try {
      signedDocument.writeTo(stream);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void openXAdESBaseline_LTSiganture() throws IOException {
    Container container = ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withDataFile(DATA_FILE, TEXT_PLAIN).
        withConfiguration(configuration).
        build();

    byte[] signatureBytes = FileUtils.readFileToByteArray(new File(BASELINE_LT_SIGNATURE));

    Signature signature = SignatureBuilder.
        aSignature(container).
        openAdESSignature(signatureBytes);
    container.addSignature(signature);

    ValidationResult validationResult = container.validate();
    System.out.println(validationResult.getReport());
  }

  @Test
  public void createSignature1XML() throws FileNotFoundException {

    org.digidoc4j.DigestAlgorithm digestAlgorithm = org.digidoc4j.DigestAlgorithm.SHA512;

    facade.setSignatureDigestAlgorithm(digestAlgorithm);

    String signaturePolicyId = "http://www.example.com/policy1.txt";
    DigestAlgorithm signaturePolicyHashAlgo = DigestAlgorithm.SHA256;
    String signaturePolicyDescription = "Policy text to digest";
    byte[] signaturePolicyDescriptionBytes = signaturePolicyDescription.getBytes();
    byte[] digestedBytes = DSSUtils.digest(signaturePolicyHashAlgo,
        signaturePolicyDescriptionBytes);

    Policy policy = new Policy();
    policy.setId(signaturePolicyId);
    policy.setDigestAlgorithm(signaturePolicyHashAlgo);
    policy.setDigestValue(digestedBytes);

    facade.setSignaturePolicy(policy);

    List<DataFile> dataFilesToSign = new ArrayList<>();
    dataFilesToSign.add(new DataFile(DATA_FILE, TEXT_PLAIN));

    X509Certificate signingCert = TestSigningHelper.getSigningCert();
    facade.setSigningCertificate(signingCert);

    byte[] dataToSign = facade.getDataToSign(dataFilesToSign);
    byte[] digestToSign = DSSUtils.digest(digestAlgorithm.getDssDigestAlgorithm(), dataToSign);
    byte[] signatureValue = TestSigningHelper.sign(digestToSign, digestAlgorithm);

    DSSDocument signedDocument = facade.signDocument(signatureValue, dataFilesToSign);

    OutputStream stream =  new FileOutputStream(SIGNATURE_1);

    try {
      signedDocument.writeTo(stream);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void createSignature2XML() throws FileNotFoundException {

    org.digidoc4j.DigestAlgorithm digestAlgorithm = org.digidoc4j.DigestAlgorithm.SHA512;

    facade.setSignatureDigestAlgorithm(digestAlgorithm);

    String signaturePolicyId = "http://www.example.com/policy2.txt";
    DigestAlgorithm signaturePolicyHashAlgo = DigestAlgorithm.SHA256;
    String signaturePolicyDescription = "Policy text to digest";
    byte[] signaturePolicyDescriptionBytes = signaturePolicyDescription.getBytes();
    byte[] digestedBytes = DSSUtils.digest(signaturePolicyHashAlgo,
        signaturePolicyDescriptionBytes);

    Policy policy = new Policy();
    policy.setId(signaturePolicyId);
    policy.setDigestAlgorithm(signaturePolicyHashAlgo);
    policy.setDigestValue(digestedBytes);

    facade.setSignaturePolicy(policy);

    List<DataFile> dataFilesToSign = new ArrayList<>();
    dataFilesToSign.add(new DataFile(DATA_FILE, TEXT_PLAIN));

    X509Certificate signingCert = TestSigningHelper.getSigningCert();
    facade.setSigningCertificate(signingCert);

    byte[] dataToSign = facade.getDataToSign(dataFilesToSign);
    byte[] digestToSign = DSSUtils.digest(digestAlgorithm.getDssDigestAlgorithm(), dataToSign);
    byte[] signatureValue = TestSigningHelper.sign(digestToSign, digestAlgorithm);

    DSSDocument signedDocument = facade.signDocument(signatureValue, dataFilesToSign);

    OutputStream stream =  new FileOutputStream(SIGNATUR_2);

    try {
      signedDocument.writeTo(stream);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void createTwoSignaturesContainer() throws IOException {
    Container container = ContainerBuilder.
        aContainer(BDOC_CONTAINER_TYPE).
        withDataFile(DATA_FILE, TEXT_PLAIN).
        withConfiguration(configuration).
        build();

    byte[] signatureBytes1 = FileUtils.readFileToByteArray(new File(SIGNATURE_1));

    Signature signature1 = SignatureBuilder.
        aSignature(container).
        openAdESSignature(signatureBytes1);
    container.addSignature(signature1);


    byte[] signatureBytes2 = FileUtils.readFileToByteArray(new File(SIGNATUR_2));

    Signature signature2 = SignatureBuilder.
        aSignature(container).
        openAdESSignature(signatureBytes2);
    container.addSignature(signature2);
    container.saveAsFile(BDOC_FILE);

    ValidationResult validationResult = container.validate();
    System.out.println(validationResult.getReport());

  }

  @Test
  public void openTwoSignaturesContainer_isNotValid() throws Exception {

    InputStream stream = FileUtils.openInputStream(new File(BDOC_FILE));
    Container loadContainer = ContainerBuilder.
        aContainer(BDOC).
        fromStream(stream).
        withConfiguration(configuration).
        build();

    ValidationResult streamValidate = loadContainer.validate();
    System.out.println(streamValidate.getReport());
    System.out.println(streamValidate.getErrors());
  }

}
