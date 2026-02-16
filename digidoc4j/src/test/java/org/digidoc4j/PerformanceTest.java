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

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.joran.spi.JoranException;
import ch.qos.logback.core.util.StatusPrinter;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.RandomUtils;
import org.digidoc4j.impl.ddoc.ConfigManagerInitializer;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.test.TestAssert;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@State(Scope.Benchmark)
@Disabled
public class PerformanceTest {

  private static final PKCS12SignatureToken pkcs12SignatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/sign_RSA_from_TEST_of_ESTEIDSK2015.p12", "1234".toCharArray());
  private Path testFolder;

  @Test
  void startPerformanceTests() throws Exception {
    Options opt = new OptionsBuilder()
            .include(PerformanceTest.class.getSimpleName())
            .forks(1)
            .warmupIterations(0)
            .warmupTime(TimeValue.seconds(0))
            .mode(Mode.SingleShotTime)
            .resultFormat(ResultFormatType.JSON)
            .timeUnit(TimeUnit.MILLISECONDS)
            .result("target/jmh-results.json")
            .build();

    new Runner(opt).run();
  }

  @Setup(Level.Trial)
  public void setUp() {
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

  @Setup(Level.Trial)
  public void beforeBenchmark() throws IOException {
    Path targetDir = Paths.get(System.getProperty("user.dir"), "target");
    Files.createDirectories(targetDir);
    testFolder = Files.createTempDirectory(targetDir, "perf-test-");
  }

  @TearDown(Level.Trial)
  public void afterBenchmark() throws IOException {
    if (testFolder != null) {
      FileUtils.deleteDirectory(testFolder.toFile());
    }
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void validateTestBDocTmSignatures(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void validateTestAsiceSignatures(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-asice.asice",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void validateTestDdocSignaturesInAsics(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/ddoc-valid.asics",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void validateTestAsiceSignaturesInAsics(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-asice-in-asics.asics",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void validateTestBdocTmSignaturesInAsics(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-bdoc-tm-in-asics.asics",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void validateTestDDocSignatures(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/ddoc-valid.ddoc",
            setup.configuration
    ));
  }

@Benchmark
@Threads(20)
@Measurement(iterations = 1000)
  public void validateTestBDocTmSignaturesInThreads(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc",
            setup.configuration
    ));
  }

@Benchmark
@Threads(20)
@Measurement(iterations = 1000)
  public void validateTestAsiceSignaturesInThreads(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-asice.asice",
            setup.configuration
    ));
  }

@Benchmark
@Threads(20)
@Measurement(iterations = 1000)
  public void validateTestDdocSignaturesInAsicsInThreads(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/ddoc-valid.asics",
            setup.configuration
    ));
  }

@Benchmark
@Threads(20)
@Measurement(iterations = 1000)
  public void validateTestDDocSignaturesInThreads(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/ddoc-valid.ddoc",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void validateTestBdocLargeContainer(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/bdoc-tm-with-large-data-file.bdoc",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void validateTestAsiceLargeContainer(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/asice-with-large-data-file.asice",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void validateTestDdocLargeContainer(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/ddoc-with-large-data-file.ddoc",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void validateTestDdocLargeContainerInAsics(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/ddoc-with-large-data-file.asics",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1)
  public void validateBDocWith1000Signatures(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/bdoc-tm-1000-signatures.bdoc",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1)
  public void validateAsiceWith1000Signatures(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/asice-1000-signatures.asice",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1)
  public void validateDddocWith1000Signatures(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/ddoc-1000-signatures.ddoc",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1)
  public void validateDdocWith1000SignaturesInAsics(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/ddoc-1000-signatures.asics",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 5)
  public void validateAsicsWith100Timestamps(BenchmarkSetup setup) {
    TestAssert.assertContainerIsValid(ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/asics-100-timestamps.asics",
            setup.configuration
    ));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void openBDocTmContainerDetails(BenchmarkSetup setup) {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc",
            setup.configuration
    );
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
    Signature signature = container.getSignatures().get(0);
    assertEquals("id-6a5d6671af7a9e0ab9a5e4d49d69800d", signature.getId());
    assertEquals(1457964829000L, signature.getTrustedSigningTime().getTime());
    assertEquals("ESTEID", signature.getSigningCertificate().getSubjectName(X509Cert.SubjectName.O));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void openAsiceContainerDetails(BenchmarkSetup setup) {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-asice.asice",
            setup.configuration
    );
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
    Signature signature = container.getSignatures().get(0);
    assertEquals("id-8c2a30729f251c6cb8336844b97f0657", signature.getId());
    assertEquals(1542975844000L, signature.getTrustedSigningTime().getTime());
    assertEquals("ESTEID", signature.getSigningCertificate().getSubjectName(X509Cert.SubjectName.O));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void openDdocContainerDetails(BenchmarkSetup setup) {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/ddoc-valid.ddoc",
            setup.configuration
    );
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
    Signature signature = container.getSignatures().get(0);
    assertEquals("S0", signature.getId());
    assertEquals(1542979861000L, signature.getTrustedSigningTime().getTime());
    assertEquals("ESTEID", signature.getSigningCertificate().getSubjectName(X509Cert.SubjectName.O));
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void openNonCompositeAsicsContainerDetails(BenchmarkSetup setup) {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/testtimestamp.asics",
            setup.configuration
    );
    assertEquals("test.txt", container.getDataFiles().get(0).getName());
    assertEquals("ASICS", container.getType());
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void openDdocInAsicsContainerDetails(BenchmarkSetup setup) {
    CompositeContainer container = (CompositeContainer) ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/ddoc-valid.asics",
            setup.configuration
    );
    assertEquals("ddoc-valid.ddoc", container.getDataFiles().get(0).getName());
    assertEquals("ASICS", container.getType());
    assertEquals("test.txt", container.getNestedContainerDataFiles().get(0).getName());
    assertEquals("DDOC", container.getNestedContainerType());
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 1000)
  public void openAsiceInAsicsContainerDetails(BenchmarkSetup setup) {
    CompositeContainer container = (CompositeContainer) ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-asice-in-asics.asics",
            setup.configuration
    );
    assertEquals("valid-asice.asice", container.getDataFiles().get(0).getName());
    assertEquals("ASICS", container.getType());
    assertEquals("test.txt", container.getNestedContainerDataFiles().get(0).getName());
    assertEquals("ASICE", container.getNestedContainerType());
  }

  @Benchmark
  @Threads(20)
  @Measurement(iterations = 1000)
  public void saveExistingContainerOnDisk(BenchmarkSetup setup) {
    Container container = ContainerOpener.open(
            "src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc",
            setup.configuration
    );
    File file = container.saveAsFile(testFolder.resolve(RandomUtils.nextInt() + ".bdoc").toString());
    assertTrue(file.exists());
    assertTrue(file.length() > 0);
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 10)
  public void loadingTSL(Blackhole blackhole) {
    TSLCertificateSource tsl = new Configuration(Configuration.Mode.PROD).getTSL();
    tsl.invalidateCache();
    tsl.refresh();
    blackhole.consume(tsl);
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 50)
  public void createAsicSignature(BenchmarkSetup setup) {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-asice.asice", setup.configuration);
    container.addSignature(SignatureBuilder.aSignature(container)
            .withSignatureDigestAlgorithm(DigestAlgorithm.SHA256)
            .withSignatureProfile(SignatureProfile.LT)
            .withSignatureToken(pkcs12SignatureToken)
            .invokeSigning());
  }

  @Benchmark
  @Threads(1)
  @Measurement(iterations = 50)
  public void extendAsicSignature(BenchmarkSetup setup) {
    Container container = ContainerOpener.open("src/test/resources/testFiles/valid-containers/valid-asice-esteid2018.asice", setup.configuration);
    container.extendSignatureProfile(SignatureProfile.LTA);
  }

  /*
   * RESTRICTED METHODS
   */

  @State(Scope.Benchmark)
  public static class BenchmarkSetup {
    public Configuration configuration;
    public ConfigManagerInitializer configManagerInitializer;

    @Setup(Level.Trial)
    public void setUp() {
      configuration = new Configuration(Configuration.Mode.TEST);
      configManagerInitializer = new ConfigManagerInitializer();
      configManagerInitializer.initConfigManager(configuration);
    }
  }
}
