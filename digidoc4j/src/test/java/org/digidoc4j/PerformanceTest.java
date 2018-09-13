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

import java.io.File;
import java.nio.file.Paths;
import java.util.List;

import org.databene.contiperf.PerfTest;
import org.databene.contiperf.junit.ContiPerfRule;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;
import org.digidoc4j.test.TestAssert;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.joran.spi.JoranException;
import ch.qos.logback.core.util.StatusPrinter;

@Ignore
public class PerformanceTest extends AbstractTest {

  private static final ConfigManagerInitializer configManagerInitializer = new ConfigManagerInitializer();
  private static final int INVOCATIONS = 1000;

  @Rule
  public ContiPerfRule performanceTestRule = new ContiPerfRule();

  @BeforeClass
  public static void beforeClass() {
    LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
    try {
      JoranConfigurator configurator = new JoranConfigurator();
      configurator.setContext(context);
      context.reset();
      configurator.doConfigure(new File("src/test/resources/performance-test.xml"));
    } catch (JoranException je) {
      // StatusPrinter will handle this
    }
    StatusPrinter.printInCaseOfErrorsOrWarnings(context);

  }

  @Test
  @PerfTest(invocations = INVOCATIONS, threads = 1)
  public void validateTestBDocTmSignatures() throws Exception {
    TestAssert.assertContainerIsValid(this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc")));
  }

  @Test
  @PerfTest(invocations = INVOCATIONS, threads = 20)
  public void validateTestBDocTmSignaturesInThreads() throws Exception {
    TestAssert.assertContainerIsValid(this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc")));
    TestAssert.assertContainerIsValid(this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/IB-4185_bdoc21_TM_mimetype_with_BOM_TEST.bdoc")));
    this.validateInvalidContainer("src/test/resources/testFiles/invalid-containers/bdoc-tm-ocsp-revoked.bdoc", "The past signature validation is not conclusive!");
  }

  @Test
  @PerfTest(invocations = INVOCATIONS, threads = 1)
  public void validateLargeContainer() throws Exception {
    TestAssert.assertContainerIsValid(this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc")));
  }

  @Test
  @PerfTest(invocations = 1, threads = 1)
  public void validateBDocWith1000Signatures() throws Exception {
    TestAssert.assertContainerIsValid(this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/bdoc-tm-1000-signatures.bdoc")));
  }

  @Test
  @PerfTest(invocations = INVOCATIONS, threads = 1)
  public void openBDocTmContainerDetails() throws Exception {
    Container container = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc"));
    Assert.assertEquals("test.txt", container.getDataFiles().get(0).getName());
    Signature signature = container.getSignatures().get(0);
    Assert.assertEquals("id-6a5d6671af7a9e0ab9a5e4d49d69800d", signature.getId());
    Assert.assertEquals(1457964829000L, signature.getTrustedSigningTime().getTime());
    Assert.assertEquals("ESTEID", signature.getSigningCertificate().getSubjectName(X509Cert.SubjectName.O));
  }

  @Test
  @PerfTest(invocations = INVOCATIONS, threads = 20)
  public void saveExistingContainerOnDisk() throws Exception {
    Container container = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc"));
    File file = container.saveAsFile(this.getFileBy("bdoc"));
    Assert.assertTrue(file.exists());
    Assert.assertTrue(file.length() > 0);
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
    Container container = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc"));
    this.createSignatureBy(container, SignatureProfile.LT_TM, DigestAlgorithm.SHA256, this.pkcs12SignatureToken);
  }

  @Test
  @PerfTest(invocations = 50, threads = 1)
  public void createAsicSignature() throws Exception {
    Container container = this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc"));
    this.createSignatureBy(container, SignatureProfile.LT, DigestAlgorithm.SHA256, this.pkcs12SignatureToken);
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
    //this.configuration.getTSL().refresh();
    this.configManagerInitializer.initConfigManager(this.configuration);
  }

  private void validateInvalidContainer(String containerLocation, String expectedError) {
    SignatureValidationResult result = this.openContainerByConfiguration(Paths.get(containerLocation)).validate();
    List<DigiDoc4JException> errors = result.getErrors();
    Assert.assertEquals(1, errors.size());
    Assert.assertEquals(expectedError, errors.get(0).getMessage());
  }

}
