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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.databene.contiperf.PerfTest;
import org.databene.contiperf.junit.ContiPerfRule;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;
import ee.sk.digidoc.factory.DigiDocFactory;
import ee.sk.utils.ConfigManager;

@Ignore
public class PerformanceTest {

  private static final Configuration configuration = new Configuration(Configuration.Mode.TEST);
  private static final ConfigManagerInitializer configManagerInitializer = new ConfigManagerInitializer();

  @Rule
  public ContiPerfRule performanceTestRule = new ContiPerfRule();
  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();
  private Container container;
  private SignedDoc jDigidocContainer;

  @Before
  public void setUp() throws Exception {
    configuration.getTSL().refresh();
    configManagerInitializer.initConfigManager(configuration);
    container = openContainer("testFiles/valid-containers/valid-bdoc-tm.bdoc", configuration);
    jDigidocContainer = openContainerWithJdigidoc("testFiles/valid-containers/valid-bdoc-tm.bdoc");
  }

  @Test
  @PerfTest(invocations = 1000, threads = 1)
  public void validateTestBDocTmSignatures() throws Exception {
    assertContainerValid("testFiles/valid-containers/valid-bdoc-tm.bdoc");
  }

  @Test
  @PerfTest(invocations = 1000, threads = 1)
  public void validateTestBDocTmWithJDigidoc() throws Exception {
    assertContainerValidWithJDigiDoc("testFiles/valid-containers/valid-bdoc-tm.bdoc");
  }

  @Test
  @PerfTest(invocations = 1000, threads = 20)
  public void validateTestBDocTmSignaturesInThreads() throws Exception {
    assertContainerValid("testFiles/valid-containers/valid-bdoc-tm.bdoc");
    assertContainerValid("testFiles/valid-containers/IB-4185_bdoc21_TM_mimetype_with_BOM_TEST.bdoc");
    validateInvalidContainer("testFiles/invalid-containers/bdoc-tm-ocsp-revoked.bdoc", "The past signature validation is not conclusive!");
  }

  @Test
  @PerfTest(invocations = 1000, threads = 20)
  public void validateTestBDocTmWithJDigidocInThreads() throws Exception {
    assertContainerValidWithJDigiDoc("testFiles/valid-containers/valid-bdoc-tm.bdoc");
    assertContainerValidWithJDigiDoc("testFiles/valid-containers/IB-4185_bdoc21_TM_mimetype_with_BOM_TEST.bdoc");
    validateInvalidContainerWithJDigidoc("testFiles/invalid-containers/bdoc-tm-ocsp-revoked.bdoc", "ERROR: 91 - Certificate has been revoked!");
  }

  @Test
  @PerfTest(invocations = 1000, threads = 1)
  public void validateLargeContainer() throws Exception {
    assertContainerValid("testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc");
  }

  @Test
  @PerfTest(invocations = 1000, threads = 1)
  public void validateLargeContainerWithJDigidoc() throws Exception {
    assertContainerValidWithJDigiDoc("testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc");
  }

  @Test
  @PerfTest(invocations = 1, threads = 1)
  public void validateBDocWith1000Signatures() throws Exception {
    assertContainerValid("testFiles/valid-containers/bdoc-tm-1000-signatures.bdoc");
  }

  @Test
  @PerfTest(invocations = 1, threads = 1)
  public void validateBDocWith1000SignaturesWithJDigidoc() throws Exception {
    assertContainerValidWithJDigiDoc("testFiles/valid-containers/bdoc-tm-1000-signatures.bdoc");
  }

  @Test
  @PerfTest(invocations = 1000, threads = 1)
  public void openBDocTmContainerDetails() throws Exception {
    Container container = openContainer("testFiles/valid-containers/valid-bdoc-tm.bdoc", configuration);
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
    Signature signature = container.getSignatures().get(0);
    assertEquals("id-6a5d6671af7a9e0ab9a5e4d49d69800d", signature.getId());
    assertEquals(1457964829000L, signature.getTrustedSigningTime().getTime());
    assertEquals("ESTEID", signature.getSigningCertificate().getSubjectName(X509Cert.SubjectName.O));
  }

  @Test
  @PerfTest(invocations = 1000, threads = 1)
  public void openBDocTmContainerDetailsWithJdigidoc() throws Exception {
    SignedDoc container = openContainerWithJdigidoc("testFiles/valid-containers/valid-bdoc-tm.bdoc");
    assertEquals("test.txt", container.getDataFile(0).getFileName());
    ee.sk.digidoc.Signature signature = container.getSignature(0);
    assertEquals("id-6a5d6671af7a9e0ab9a5e4d49d69800d", signature.getId());
    assertEquals(1457964829000L, signature.getSignatureProducedAtTime().getTime());
    assertEquals("1.2.840.113549.1.9.1=#1609706b6940736b2e6565,CN=TEST of ESTEID-SK 2011,O=AS Sertifitseerimiskeskus,C=EE", signature.getCertID(0).getIssuer());
  }

  @Test
  @PerfTest(invocations = 1000, threads = 20)
  public void saveExistingContainerOnDisk() throws Exception {
    String path = testFolder.newFile().getPath();
    File file = container.saveAsFile(path);
    assertTrue(file.exists());
    assertTrue(file.length() > 0);
  }

  @Test
  @PerfTest(invocations = 1000, threads = 20)
  public void saveExistingContainerOnDiskWithJDigidoc() throws Exception {
    File file = testFolder.newFile();
    jDigidocContainer.writeToFile(file);
    assertTrue(file.exists());
    assertTrue(file.length() > 0);
  }

  @Test
  @PerfTest(invocations = 10, threads = 1)
  public void loadingTSL() throws Exception {
    TSLCertificateSource tsl = new Configuration(Configuration.Mode.PROD).getTSL();
    tsl.invalidateCache();
    tsl.refresh();
  }

  @Test
  @PerfTest(invocations = 50, threads = 1)
  public void createBDocTmSignature() throws Exception {
    signContainer(container, SignatureProfile.LT_TM);
  }

  @Test
  @PerfTest(invocations = 50, threads = 1)
  public void createAsicSignature() throws Exception {
    signContainer(container, SignatureProfile.LT);
  }

  private void assertContainerValid(String containerPath) {
    ValidationResult result = validateContainer(containerPath, configuration);
    assertTrue(result.isValid());
  }

  private ValidationResult validateContainer(String containerPath, Configuration configuration) {
    Container container = openContainer(containerPath, configuration);
    return container.validate();
  }

  private void validateInvalidContainer(String containerPath, String expectedError) {
    ValidationResult result = validateContainer(containerPath, configuration);
    List<DigiDoc4JException> errors = result.getErrors();
    assertEquals(1, errors.size());
    assertEquals(expectedError, errors.get(0).getMessage());
  }

  private Container openContainer(String containerPath, Configuration configuration) {
    return openContainerBuilder(containerPath).
          withConfiguration(configuration).
          build();
  }

  private ContainerBuilder openContainerBuilder(String containerPath) {
    return ContainerBuilder.
        aContainer(Constant.BDOC_CONTAINER_TYPE).
        fromExistingFile(containerPath);
  }

  private void assertContainerValidWithJDigiDoc(String containerFilePath) throws DigiDocException {
    List errors = validateContainerWithJDigidoc(containerFilePath);
    assertTrue(getJDigiDocErrorMessage(errors), errors.isEmpty());
  }

  private List validateContainerWithJDigidoc(String containerFilePath) throws DigiDocException {
    boolean isBdoc = true;
    List errors = new ArrayList();
    DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
    digFac.readSignedDocOfType(containerFilePath, isBdoc, errors);
    return errors;
  }

  private void validateInvalidContainerWithJDigidoc(String containerFilePath, String expectedError) throws DigiDocException {
    List errors = validateContainerWithJDigidoc(containerFilePath);
    assertEquals(1, errors.size());
    assertEquals(expectedError, errors.get(0).toString());
  }

  private SignedDoc openContainerWithJdigidoc(String containerFilePath) throws DigiDocException {
    boolean isBdoc = true;
    List errors = new ArrayList();
    DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
    return digFac.readSignedDocOfType(containerFilePath, isBdoc, errors);
  }

  private String getJDigiDocErrorMessage(List errors) {
    String msg = "";
    for(Object error : errors) {
      msg += error.toString() + "; ";
    }
    return msg;
  }

  private void signContainer(Container container, SignatureProfile signatureProfile) {
    SignatureToken signatureToken = new PKCS12SignatureToken("testFiles/p12/signout.p12", "test".toCharArray());
    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(signatureProfile).
        withSignatureToken(signatureToken).
        invokeSigning();
    container.addSignature(signature);
  }
}
