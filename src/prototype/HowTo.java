/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package prototype;

import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.https.FileCacheDataLoader;
import eu.europa.ec.markt.dss.validation102853.ocsp.OnlineOCSPSource;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.tsl.TrustedListsCertificateSource;
import org.digidoc4j.*;
import org.digidoc4j.Container.SignatureProfile;
import org.digidoc4j.signers.PKCS12Signer;

import java.io.File;

import static java.util.Arrays.asList;

public class HowTo {
  public static void main(String[] args) {
    test();
  }

  private static void test() {
//    Configuration configuration = new Configuration(Configuration.Mode.PROD);
//    configuration.setOCSPAccessCertificateFileName("testFiles/ocsp_juurdepaasutoend.p12d");
//    configuration.setOCSPAccessCertificatePassword("0vRsI0XQ".toCharArray());
//    configuration.setValidationPolicy("conf/test_constraint.xml");

    Configuration configuration = new Configuration(Configuration.Mode.TEST);
    Container container = Container.create(configuration);
    SignatureParameters signatureParameters = new SignatureParameters();
    SignatureProductionPlace productionPlace = new SignatureProductionPlace();
    productionPlace.setCity("Nõmme");
    signatureParameters.setProductionPlace(productionPlace);
    signatureParameters.setRoles(asList("manakeri"));
    container.setSignatureParameters(signatureParameters);
    container.setSignatureProfile(SignatureProfile.LT_TM);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(new PKCS12Signer("testFiles/signout.p12", "test".toCharArray()));
//    Container container = Container.open("util/faulty/bdoc21-bad-nonce-content.bdoc");
    container.save("prototype.bdoc");
    ValidationResult result = container.validate();
    System.out.println(result.getReport());
//    Container container = Container.open("BDOC_2.1_TS.bdoc", configuration);
//    container.extendTo(Container.SignatureProfile.TSA);
//    container.save("BDOC_2.1_TSA.bdoc");
//    ValidationResult result = container.validate();
//    if (!result.isValid()) {
//      System.out.println(result.getReport());
//    }
  }

  public static void validate() {
    DSSDocument toValidateDocument = new FileDocument("util/plugtest_asice/Signature-A-EE_CBTS-1.asice");
    SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(toValidateDocument);
//    CommonsDataLoader commonsDataLoader = new CommonsDataLoader();
    CommonCertificateVerifier verifier = new CommonCertificateVerifier();

//    OnlineCRLSource crlSource = new OnlineCRLSource();
//    crlSource.setDataLoader(commonsDataLoader);
//    verifier.setCrlSource(null);
    OnlineOCSPSource ocspSource = new OnlineOCSPSource();
    verifier.setOcspSource(ocspSource);

    final FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
    File cacheFolder = new File("/tmp");

    fileCacheDataLoader.setFileCacheDirectory(cacheFolder);
    final TrustedListsCertificateSource certificateSource = new TrustedListsCertificateSource();
    certificateSource.setLotlUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml");
    certificateSource.setCheckSignature(false);
    certificateSource.setDataLoader(fileCacheDataLoader);

    certificateSource.init();

    verifier.setTrustedCertSource(certificateSource);
    verifier.setDataLoader(fileCacheDataLoader);
    validator.setCertificateVerifier(verifier);
    final Reports reports = validator.validateDocument(new File("conf/test_constraint.xml"));
    reports.print();
  }
}
