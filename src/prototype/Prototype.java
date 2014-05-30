package prototype;

import ee.sk.utils.SKOnlineOCSPSource;
import eu.europa.ec.markt.dss.DigestAlgorithm;
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
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.https.CommonsDataLoader;
import eu.europa.ec.markt.dss.validation102853.report.SimpleReport;
import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;
import eu.europa.ec.markt.dss.validation102853.tsp.OnlineTSPSource;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Prototype for testing purposes
 */
public class Prototype {
  /**
   * @param args List of arguments for main method. No arguments expected
   * @throws CertificateException     if there is a problem with the certificate
   * @throws NoSuchAlgorithmException if the cryptographic algorithm is unknown
   * @throws KeyStoreException        if there is a generic KeyStore exception
   * @throws IOException              if there is any IO failure
   */
  public static void main(String[] args) throws CertificateException, NoSuchAlgorithmException,
      KeyStoreException, IOException {
    sign();
    //validate();
  }
  //rm -rf test.bdoc, META-INF/.DS_Store && zip -0 -X test.bdoc mimetype && zip -r -D test.bdoc * -x mimetype && unzip -l test.bdoc

  private static void sign() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
    DSSDocument toSignDocument = new FileDocument("test.txt");
    // File file = new File("209MBFile.tmp");
    // File file = new File("test.txt");
    // DSSDocument toSignDocument = new FileDocument(file);
    AbstractSignatureTokenConnection token = new Pkcs12SignatureToken("test", "signout.p12");
    DSSPrivateKeyEntry privateKey = token.getKeys().get(0);

    SignatureParameters parameters = new SignatureParameters();
    parameters.setSignatureLevel(SignatureLevel.ASiC_S_BASELINE_LT);
    parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
    parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

    // Create XAdES service for signature
    CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

    CommonsDataLoader dataLoader = new CommonsDataLoader();

    //final String lotlUrl = "file://tl-mp.xml";
//    final String lotlUrl = "http://sr.riik.ee/tsl/estonian-tsl.xml";
    //final String lotlUrl = "http://ftp.getFileId.eesti.ee/pub/getFileId/tsl/trusted-test-tsl.xml";
    final String lotlUrl = "file:trusted-test-tsl.xml";
    TrustedListsCertificateSource tslCertificateSource = new TrustedListsCertificateSource();
    tslCertificateSource.setDataLoader(dataLoader);
    tslCertificateSource.setLotlUrl(lotlUrl);
    tslCertificateSource.setCheckSignature(false);
    tslCertificateSource.init();
    commonCertificateVerifier.setTrustedCertSource(tslCertificateSource);

    SKOnlineOCSPSource onlineOCSPSource = new SKOnlineOCSPSource();
    //onlineOCSPSource.setDataLoader(dataLoader);
    commonCertificateVerifier.setOcspSource(onlineOCSPSource);

    //XAdESService service = new XAdESService(commonCertificateVerifier);
    ASiCEService service = new ASiCEService(commonCertificateVerifier);

    service.setTspSource(new OnlineTSPSource("http://tsa01.quovadisglobal.com/TSS/HttpTspServer"));


    //parameters.setPrivateKeyEntry(privateKey);
//    InputStream inStream = new FileInputStream("signout.p12");
//    KeyStore ks = KeyStore.getInstance("PKCS12");
//    ks.load(inStream, "test".toCharArray());
//    String alias = ks.aliases().nextElement();
    parameters.setSigningCertificate(privateKey.getCertificate());

    byte[] dataToSign = service.getDataToSign(toSignDocument, parameters);

    byte[] signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

    DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
    signedDocument.save("document.bdoc");
  }


  private static void validate() {
    AbstractSignatureTokenConnection token = new Pkcs12SignatureToken("test", "signout.p12");
    DSSPrivateKeyEntry privateKey = token.getKeys().get(0);
    final X509Certificate[] certificateChain = privateKey.getCertificateChain();
    final X509Certificate trustedCertificate = certificateChain[0];

//    DSSDocument detachedDocument = new FileDocument("test.txt");

// / Already signed document
    String toValidateFilePath = "documentTS/test.bdoc";
//    String toValidateFilePath = "cpp_teek_document.bdoc";
    DSSDocument document = new FileDocument(toValidateFilePath);
    SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

    CommonCertificateVerifier verifier = new CommonCertificateVerifier();
    AlwaysValidOCSPSource ocspSource = new AlwaysValidOCSPSource();
    verifier.setOcspSource(ocspSource);

    final MockTSLCertificateSource trustedCertSource = new MockTSLCertificateSource();
    ServiceInfo mockServiceInfo = new MockServiceInfo();
    trustedCertSource.addCertificate(trustedCertificate, mockServiceInfo);
    verifier.setTrustedCertSource(trustedCertSource);
    validator.setCertificateVerifier(verifier);
    validator.validateDocument();

    SimpleReport simpleReport = validator.getSimpleReport();
    System.out.println(simpleReport);
//    DetailedReport detailedReport = validator.getDetailedReport();
//    System.out.println(detailedReport);
//    DiagnosticData diagnosticData = validator.getDiagnosticData();
//    System.out.println(diagnosticData);

  }
}
