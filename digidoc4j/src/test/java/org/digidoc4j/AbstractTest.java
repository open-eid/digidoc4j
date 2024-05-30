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

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.AiaSourceFactory;
import org.digidoc4j.impl.CommonOCSPSource;
import org.digidoc4j.impl.ConfigurationSingeltonHolder;
import org.digidoc4j.impl.OcspDataLoaderFactory;
import org.digidoc4j.impl.TspDataLoaderFactory;
import org.digidoc4j.impl.asic.AsicFileContainerParser;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicStreamContainerParser;
import org.digidoc4j.impl.asic.asice.AsicEContainer;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainer;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.asics.AsicSContainer;
import org.digidoc4j.impl.asic.xades.XadesSigningDssFacade;
import org.digidoc4j.impl.ddoc.DDocContainer;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.test.TargetTemporaryFolderRule;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.digidoc4j.test.util.TestSigningUtil;
import org.digidoc4j.test.util.TestTSLUtil;
import org.digidoc4j.utils.Helper;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.internal.AssumptionViolatedException;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.function.Consumer;

import static org.digidoc4j.Container.DocumentType.ASICE;
import static org.digidoc4j.Container.DocumentType.ASICS;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.digidoc4j.Container.DocumentType.DDOC;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public abstract class AbstractTest extends ConfigurationSingeltonHolder {

  private static final Logger LOGGER = LoggerFactory.getLogger(AbstractTest.class);

  protected static final String BDOC_WITH_TM_SIG = "src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc";
  protected static final String BDOC_WITH_TM_AND_TS_SIG = "src/test/resources/testFiles/valid-containers/bdoc-with-tm-and-ts-signature.bdoc";
  protected static final String BDOC_WITH_B_EPES_SIG = "src/test/resources/testFiles/valid-containers/bdoc-with-b-epes-signature.bdoc";
  protected static final String BDOC_WITH_NO_SIG = "src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc";
  protected static final String ASIC_WITH_NO_SIG = "src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc";
  protected static final String ASICE_WITH_TS_SIG_BUT_BDOC_EXTENSION = "src/test/resources/testFiles/valid-containers/one_signature.bdoc";
  protected static final String ASICE_WITH_TS_SIG = "src/test/resources/testFiles/valid-containers/valid-asice.asice";
  protected static final String ASICE_WITH_NO_SIG = "src/test/resources/testFiles/valid-containers/container_without_signatures.asice";
  protected static final String ASICS_WITH_TS = "src/test/resources/testFiles/valid-containers/ddoc-valid.asics";
  protected static final String ASICS_WITH_NO_SIG = "src/test/resources/testFiles/valid-containers/container_without_signatures.asics";
  protected static final String DDOC_TEST_FILE = "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc";

  protected static final String USER_AGENT_STRING = "test-user-agent";

  protected static final PKCS12SignatureToken pkcs12SignatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/sign_RSA_from_TEST_of_ESTEIDSK2015.p12", "1234".toCharArray());
  protected static final PKCS12SignatureToken pkcs12EccSignatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/sign_ECC_from_TEST_of_ESTEIDSK2015.p12", "1234".toCharArray());
  protected static final PKCS12SignatureToken pkcs12Esteid2018SignatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/sign_ECC_from_TEST_of_ESTEID2018.p12", "1234".toCharArray());
  protected Configuration configuration;

  @Rule
  public TemporaryFolder testFolder = new TargetTemporaryFolderRule("tmp");

  @Rule
  public ExpectedException expectedException = ExpectedException.none();

  @Rule
  public TestWatcher watcher = new TestWatcher() {

    private final Logger log = LoggerFactory.getLogger(AbstractTest.class);
    private long startTimestamp;

    @Override
    protected void starting(Description description) {
      String starting = String.format("Starting <%s.%s>", description.getClassName(), description.getMethodName());
      LOGGER.info(StringUtils.rightPad("-", starting.length(), '-'));
      LOGGER.info(starting);
      LOGGER.info(StringUtils.rightPad("-", starting.length(), '-'));
      this.startTimestamp = System.currentTimeMillis();
    }

    @Override
    protected void succeeded(Description description) {
      long endTimestamp = System.currentTimeMillis();
      LOGGER.info("Finished <{}.{}> - took <{}> ms", description.getClassName(), description.getMethodName(),
          endTimestamp - this.startTimestamp);
    }

    @Override
    protected void failed(Throwable e, Description description) {
      LOGGER.error(String.format("Finished <%s.%s> - failed", description.getClassName(), description.getMethodName()), e);
    }

    @Override
    protected void skipped(AssumptionViolatedException e, Description description) {
      String skipped = String.format("Skipped <%s.%s>", description.getClassName(), description.getMethodName());
      LOGGER.debug(StringUtils.rightPad("-", skipped.length(), '-'));
      LOGGER.debug(skipped);
      LOGGER.debug(StringUtils.rightPad("-", skipped.length(), '-'));
    }

  };

  @Before
  public void beforeMethod() {
    LOGGER.info("NB! Before method --> START");
    ConfigurationSingeltonHolder.reset();
    this.setGlobalMode(Configuration.Mode.TEST);
    this.before();
    LOGGER.info("NB! Before method --> END");
  }

  @After
  public void afterMethod() {
    try {
      FileUtils.deleteDirectory(this.testFolder.getRoot());
    } catch (IOException e) {
      LOGGER.warn("Unable to clean folder <{}>", this.testFolder.getRoot());
    }
    this.after();
  }

  /*
   * RESTRICTED METHODS
   */

  protected void before() {
    // Do nothing
  }

  protected void after() {
    // Do nothing
  }

  protected void setGlobalMode(Configuration.Mode mode) {
    System.setProperty("digidoc4j.mode", mode.name());
  }

  protected void clearGlobalMode() {
    System.clearProperty("digidoc4j.mode");
  }

  protected String getDDoc4JConfigurationValue(String key) {
    return this.configuration.getDDoc4JConfiguration().get(key);
  }

  protected void addCertificateToTSL(Path path, TSLCertificateSource source) {
    try (InputStream stream = new FileInputStream(path.toFile())) {
      source.addTSLCertificate(DSSUtils.loadCertificate(stream).getCertificate());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  protected AsicParseResult getParseResultFromFile(Path path) {
    return new AsicFileContainerParser(path.toString(), Configuration.getInstance()).read();
  }

  protected AsicParseResult getParseResultFromStream(String path) throws FileNotFoundException {
    return new AsicStreamContainerParser(new FileInputStream(path), Configuration.getInstance()).read();
  }

  protected Container openContainerBy(Path path) {
    return ContainerBuilder.aContainer().fromExistingFile(path.toString()).build();
  }

  protected Container openContainerByConfiguration(Path path) {
    return this.openContainerByConfiguration(path, this.configuration);
  }

  protected Container openContainerByConfiguration(Path path, Configuration configuration) {
    ContainerBuilder builder = ContainerBuilder.aContainer().fromExistingFile(path.toString());
    if (configuration != null) {
      builder.withConfiguration(configuration);
    }
    return builder.build();
  }

  @SuppressWarnings("unchecked")
  protected <T> T createEmptyContainer() {
    return (T) ContainerBuilder.aContainer().build();
  }

  @SuppressWarnings("unchecked")
  protected <T> T createEmptyContainer(Configuration configuration) {
    return (T) ContainerBuilder.aContainer().withConfiguration(configuration).build();
  }

  @SuppressWarnings("unchecked")
  protected <T> T createEmptyContainer(Class<T> clazz) {
    return (T) ContainerBuilder.aContainer().build();
  }

  @SuppressWarnings("unchecked")
  protected <T> T createEmptyContainerBy(Container.DocumentType type) {
    return (T) ContainerBuilder.aContainer(type).build();
  }

  @SuppressWarnings("unchecked")
  protected <T> T createEmptyContainerBy(Container.DocumentType type, Class<T> clazz) {
    return (T) ContainerBuilder.aContainer(type).build();
  }

  @SuppressWarnings("unchecked")
  protected <T> T createContainer(DataFile... dataFiles) {
    ContainerBuilder containerBuilder = ContainerBuilder.aContainer();
    Arrays.asList(dataFiles).forEach(containerBuilder::withDataFile);
    return (T) containerBuilder.build();
  }

  @SuppressWarnings("unchecked")
  protected <T> T createContainer(Configuration configuration, DataFile... dataFiles) {
    ContainerBuilder containerBuilder = ContainerBuilder.aContainer().withConfiguration(configuration);
    Arrays.asList(dataFiles).forEach(containerBuilder::withDataFile);
    return (T) containerBuilder.build();
  }

  @SuppressWarnings("unchecked")
  protected <T> T createContainer(Class<T> clazz, DataFile... dataFiles) {
    ContainerBuilder containerBuilder = ContainerBuilder.aContainer();
    Arrays.asList(dataFiles).forEach(containerBuilder::withDataFile);
    return (T) containerBuilder.build();
  }

  @SuppressWarnings("unchecked")
  protected <T> T createContainerBy(Container.DocumentType type, DataFile... dataFiles) {
    ContainerBuilder containerBuilder = ContainerBuilder.aContainer(type);
    Arrays.asList(dataFiles).forEach(containerBuilder::withDataFile);
    return (T) containerBuilder.build();
  }

  @SuppressWarnings("unchecked")
  protected <T> T createContainerBy(Container.DocumentType type, Class<T> clazz, DataFile... dataFiles) {
    ContainerBuilder containerBuilder = ContainerBuilder.aContainer(type);
    Arrays.asList(dataFiles).forEach(containerBuilder::withDataFile);
    return (T) containerBuilder.build();
  }

  protected Container createNonEmptyContainer() {
    return this.createNonEmptyContainerBy(Container.DocumentType.BDOC);
  }

  protected Container createNonEmptyContainerByConfiguration() {
    return ContainerBuilder.aContainer(BDOC).withConfiguration(this.configuration)
        .withDataFile(this.createTemporaryFileBy("TOP SECRET").getPath(), "text/plain").build();
  }

  protected Container createNonEmptyContainerBy(Container.DocumentType type) {
    try {
      return TestDataBuilderUtil.createContainerWithFile(this.testFolder, type, Configuration.Mode.TEST);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  protected Container createNonEmptyContainerBy(Path path) {
    return TestDataBuilderUtil.createContainerWithFile(path.toString());
  }

  protected Container createNonEmptyContainerBy(Container.DocumentType type, Path path, String mimeType) {
    return ContainerBuilder.aContainer(type).withDataFile(path.toString(), mimeType).build();
  }
  protected Container createNonEmptyContainerBy(Path path, String mimeType) {
    return ContainerBuilder.aContainer().withDataFile(path.toString(), mimeType).build();
  }

  protected Container createNonEmptyContainer(Container.DocumentType type, int filesCount) throws IOException {
    ContainerBuilder builder = ContainerBuilder.aContainer(type);
    for (int i = 0; i < filesCount; i++) {
      builder.withDataFile(this.createTemporaryFileBy("TOP SECRET").getPath(), "text/plain");
    }
    return builder.build();
  }

  protected File createTemporaryFile() throws IOException {
    return this.testFolder.newFile();
  }

  protected File createTemporaryFileBy(String name, String content) {
    try {
      File file = this.testFolder.newFile(name);
      FileUtils.writeStringToFile(file, "Banana Pancakes");
      return file;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  protected File createTemporaryFileBy(String content) {
    try {
      File file = this.testFolder.newFile();
      FileUtils.writeStringToFile(file, content);
      return file;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  protected String getFileContent(InputStream stream) {
    try {
      return IOUtils.toString(stream, StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  protected String getFileBy(String extension) {
    return this.getFileBy(extension, false);
  }

  protected String getFileBy(String extension, boolean create) {
    String file = String.format("%s/%s.%s", this.testFolder.getRoot().getPath(), RandomUtils.nextInt(), extension);
    if (create) {
      try {
        Files.createFile(Paths.get(file));
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }
    return file;
  }

  @SuppressWarnings("unchecked")
  protected <T> T createSignatureBy(Container container, SignatureToken signatureToken) {
    return (T) this.createSignatureBy(container, (SignatureProfile) null, signatureToken);
  }

  protected <T> T createSignatureBy(Container container, DigestAlgorithm digestAlgorithm, SignatureToken signatureToken) {
    return this.createSignatureBy(container, null, digestAlgorithm, signatureToken);
  }

  protected <T> T createSignatureBy(Container container, SignatureProfile signatureProfile, SignatureToken signatureToken) {
    return this.createSignatureBy(container, signatureProfile, null, signatureToken);
  }

  @SuppressWarnings("unchecked")
  protected <T> T createSignatureBy(Container container, SignatureProfile signatureProfile, DigestAlgorithm digestAlgorithm, SignatureToken signatureToken) {
    SignatureBuilder builder = SignatureBuilder.aSignature(container).withSignatureToken(signatureToken);
    if (signatureProfile != null) {
      builder.withSignatureProfile(signatureProfile);
    }
    if (digestAlgorithm != null) {
      builder.withSignatureDigestAlgorithm(digestAlgorithm);
    }
    Signature signature = builder.invokeSigning();
    container.addSignature(signature);
    return (T) signature;
  }

  protected <T> T createSignatureBy(Container.DocumentType type, SignatureToken signatureToken) {
    return this.createSignatureBy(type, null, signatureToken, Configuration.Mode.TEST);
  }

  protected <T> T createSignatureBy(Container.DocumentType type, SignatureToken signatureToken, Class<T> clazz) {
    return this.createSignatureBy(type, null, signatureToken, Configuration.Mode.TEST);
  }

  protected <T> T createSignatureBy(Container.DocumentType type, SignatureToken signatureToken, Configuration.Mode mode) {
    return this.createSignatureBy(type, null, signatureToken, mode);
  }

  protected <T> T createSignatureBy(Container.DocumentType type, SignatureToken signatureToken, Configuration configuration) {
    return this.createSignatureBy(type, null, signatureToken, configuration);
  }

  protected <T> T createSignatureBy(Container.DocumentType type, SignatureProfile signatureProfile, SignatureToken signatureToken) {
    return this.createSignatureBy(type, signatureProfile, signatureToken, Configuration.Mode.TEST);
  }

  protected <T> T createSignatureBy(Container.DocumentType type, SignatureProfile signatureProfile, SignatureToken signatureToken, Configuration.Mode mode) {
    return createSignatureBy(type, signatureProfile, signatureToken, Configuration.of(mode));
  }

  @SuppressWarnings("unchecked")
  protected <T> T createSignatureBy(Container.DocumentType type, SignatureProfile signatureProfile, SignatureToken signatureToken, Configuration configuration) {
    try {
      SignatureBuilder builder = SignatureBuilder.aSignature(TestDataBuilderUtil.createContainerWithFile(this.testFolder, type, configuration));
      if (signatureProfile != null) {
        builder.withSignatureProfile(signatureProfile);
      }
      return (T) builder.withSignatureToken(signatureToken).invokeSigning();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @SuppressWarnings("unchecked")
  protected <T> T createSignatureBy(DigestAlgorithm digestAlgorithm, SignatureToken signatureToken) {
    try {
      return (T) SignatureBuilder.aSignature(this.createNonEmptyContainer()).withSignatureDigestAlgorithm(digestAlgorithm).
          withSignatureToken(signatureToken).invokeSigning();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  protected String createSignedContainerBy(Container.DocumentType type, String extension) {
    String file = this.getFileBy(extension);
    Container container = this.createNonEmptyContainerBy(type, Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    createSignatureBy(container, SignatureProfile.LT, pkcs12SignatureToken);
    container.saveAsFile(file);
    return file;
  }

  protected String createNonEmptyLargeContainer(long size) {
    String fileName = this.getFileBy("bdoc");
    try (RandomAccessFile largeFile = new RandomAccessFile(fileName, "rw")) {
      largeFile.setLength(size);// TODO: create large file correctly
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return fileName;
  }

  public <T> void serialize(T object, String filename) {
    Helper.serialize(object, new File(filename));
  }

  public <T> T deserializer(String filename) {
    return Helper.deserializer(new File(filename));
  }

  protected DSSDocument sign(XadesSigningDssFacade facade, DigestAlgorithm digestAlgorithm) {
    return facade.signDocument(TestSigningUtil.sign(this.getDataToSign(facade), digestAlgorithm), this.createDataFilesToSign());
  }

  protected byte[] sign(byte[] dataToSign, DigestAlgorithm digestAlgorithm) {
    return pkcs12SignatureToken.sign(digestAlgorithm, dataToSign);
  }

  protected byte[] getDataToSign(XadesSigningDssFacade facade) {
    facade.setSigningCertificate(pkcs12SignatureToken.getCertificate());
    return facade.getDataToSign(this.createDataFilesToSign());
  }

  protected List<DataFile> createDataFilesToSign() {
    return Collections.singletonList(new DataFile("src/test/resources/testFiles/helper-files/test.txt", "plain/text"));
  }

  protected DataFile createBinaryDataFile(String fileName, byte[] fileContent) {
    return new DataFile(fileContent, fileName, MimeTypeEnum.BINARY.getMimeTypeString());
  }

  protected DataFile createTextDataFile(String fileName, String fileContent) {
    return new DataFile(fileContent.getBytes(StandardCharsets.UTF_8), fileName, MimeTypeEnum.TEXT.getMimeTypeString());
  }

  protected void evictTSLCache() {
    TestTSLUtil.evictCache();
  }

  protected long getTSLCacheLastModificationTime() {
    return TestTSLUtil.getCacheLastModified();
  }

  protected boolean isTSLCacheEmpty() {
    return TestTSLUtil.isTslCacheEmpty();
  }

  protected static X509Certificate openX509Certificate(String path) {
    return openX509Certificate(Paths.get(path));
  }

  protected static X509Certificate openX509Certificate(Path path) {
    try (InputStream in = Files.newInputStream(path)) {
      return openX509Certificate(in);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to load certificate from: " + path, e);
    }
  }

  protected static X509Certificate openX509Certificate(InputStream in) {
    try {
      return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    } catch (CertificateException e) {
      throw new IllegalStateException("Failed to load certificate", e);
    }
  }

  protected static CertificateToken openCertificateToken(String path) {
    return new CertificateToken(openX509Certificate(path));
  }

  protected static CertificateToken openCertificateToken(Path path) {
    return new CertificateToken(openX509Certificate(path));
  }

  protected static CertificateToken openCertificateToken(InputStream in) {
    return new CertificateToken(openX509Certificate(in));
  }

  protected XadesSigningDssFacade createSigningFacade() {
    XadesSigningDssFacade facade = new XadesSigningDssFacade();
    facade.setAiaSource(new AiaSourceFactory(configuration).create());
    facade.setCertificateSource(this.configuration.getTSL());
    facade.setOcspSource(this.createOCSPSource());
    facade.setTspSource(this.createTSPSource());
    return facade;
  }

  protected CommonOCSPSource createOCSPSource() {
    CommonOCSPSource source = new CommonOCSPSource(this.configuration);
    DataLoader loader = new OcspDataLoaderFactory(this.configuration).create();
    source.setDataLoader(loader);
    return source;
  }

  private OnlineTSPSource createTSPSource() {
    DataLoader loader = new TspDataLoaderFactory(this.configuration).create();
    OnlineTSPSource source = new OnlineTSPSource(this.configuration.getTspSource());
    source.setDataLoader(loader);
    return source;
  }

  protected void assertBDocContainer(Container container) {
    Assert.assertNotNull(container);
    Assert.assertTrue(container instanceof BDocContainer);
    Assert.assertEquals(BDOC.name(), container.getType());
  }

  protected void assertAsicEContainer(Container container) {
    Assert.assertNotNull(container);
    Assert.assertTrue(container instanceof AsicEContainer);
    Assert.assertEquals(ASICE.name(), container.getType());
  }

  protected void assertAsicSContainer(Container container) {
    Assert.assertNotNull(container);
    Assert.assertTrue(container instanceof AsicSContainer);
    Assert.assertEquals(ASICS.name(), container.getType());
  }

  protected void assertDDocContainer(Container container) {
    Assert.assertNotNull(container);
    Assert.assertTrue(container instanceof DDocContainer);
    Assert.assertEquals(DDOC.name(), container.getType());
  }

  protected void assertTimemarkSignature(Signature signature) {
    Assert.assertNotNull(signature);
    Assert.assertTrue(signature instanceof BDocSignature);
    Assert.assertEquals(SignatureProfile.LT_TM, signature.getProfile());
  }

  protected void assertLtSignature(Signature signature) {
    Assert.assertNotNull(signature);
    Assert.assertTrue(signature instanceof AsicESignature);
    Assert.assertEquals(SignatureProfile.LT, signature.getProfile());
  }

  protected void assertTimestampSignature(Signature signature) {
    Assert.assertNotNull(signature);
    Assert.assertTrue(signature instanceof AsicESignature);
    Assert.assertEquals(SignatureProfile.T, signature.getProfile());
  }

  protected void assertArchiveTimestampSignature(Signature signature) {
    Assert.assertNotNull(signature);
    Assert.assertTrue(signature instanceof AsicESignature);
    Assert.assertEquals(SignatureProfile.LTA, signature.getProfile());
  }

  protected void assertBEpesSignature(Signature signature) {
    Assert.assertNotNull(signature);
    Assert.assertTrue(signature instanceof BDocSignature);
    Assert.assertEquals(SignatureProfile.B_EPES, signature.getProfile());
  }

  protected void assertBBesSignature(Signature signature) {
    Assert.assertNotNull(signature);
    Assert.assertTrue(signature instanceof AsicESignature);
    Assert.assertEquals(SignatureProfile.B_BES, signature.getProfile());
  }

  protected static void assertValidSignature(Signature signature) {
    ValidationResult validationResult = signature.validateSignature();
    Assert.assertTrue("Expected signature to be valid", validationResult.isValid());
    assertHasNoWarnings(validationResult);
    assertHasNoErrors(validationResult);
  }

  protected static void assertValidSignatureWithWarnings(Signature signature) {
    ValidationResult validationResult = signature.validateSignature();
    Assert.assertTrue("Expected signature to be valid", validationResult.isValid());
    Assert.assertTrue("Expected validation warnings but none found", validationResult.hasWarnings());
    assertHasNoErrors(validationResult);
  }

  protected static void assertSignatureWith(Signature signature, Consumer<List<DigiDoc4JException>> errorsVerifier, Consumer<List<DigiDoc4JException>> warningsVerifier) {
    ValidationResult validationResult = signature.validateSignature();
    Assert.assertEquals(errorsVerifier == null, validationResult.isValid());
    if (errorsVerifier != null) {
      List<DigiDoc4JException> errors = validationResult.getErrors();
      Assert.assertTrue("Expected validation errors but none found", CollectionUtils.isNotEmpty(errors));
      errorsVerifier.accept(errors);
    } else {
      assertHasNoErrors(validationResult);
    }
    if (warningsVerifier != null) {
      List<DigiDoc4JException> warnings = validationResult.getWarnings();
      Assert.assertTrue("Expected validation warnings but none found", CollectionUtils.isNotEmpty(warnings));
      warningsVerifier.accept(warnings);
    } else {
      assertHasNoWarnings(validationResult);
    }
  }

  protected static void assertTimeInBounds(Date time, Instant lowerBound, Duration maxClockSkew) {
    assertTimeInBounds(time.toInstant(), lowerBound, maxClockSkew);
  }

  protected static void assertTimeInBounds(Instant time, Instant lowerBound, Duration maxClockSkew) {
    assertTimeInBounds(time, lowerBound, Instant.now(), maxClockSkew);
  }

  protected static void assertTimeInBounds(Date time, Instant lowerBound, Instant upperBound, Duration maxClockSkew) {
    assertTimeInBounds(time.toInstant(), lowerBound, upperBound, maxClockSkew);
  }

  protected static void assertTimeInBounds(Instant time, Instant lowerBound, Instant upperBound, Duration maxClockSkew) {
    assertThat(time, greaterThanOrEqualTo(lowerBound.minus(maxClockSkew)));
    assertThat(time, lessThanOrEqualTo(upperBound.plus(maxClockSkew)));
  }

  protected static void assertHasNoErrors(ValidationResult validationResult) {
    List<DigiDoc4JException> errors = validationResult.getErrors();
    Assert.assertEquals(validationResult.isValid(), CollectionUtils.isEmpty(errors));
    if (CollectionUtils.isNotEmpty(errors)) {
      Assert.fail(String.format(
              "Expected no validation errors, but found %d errors: %s",
              errors.size(), errors
      ));
    }
  }

  protected static void assertHasNoWarnings(ValidationResult validationResult) {
    List<DigiDoc4JException> warnings = validationResult.getWarnings();
    Assert.assertEquals(validationResult.hasWarnings(), CollectionUtils.isNotEmpty(warnings));
    if (CollectionUtils.isNotEmpty(warnings)) {
      Assert.fail(String.format(
              "Expected no validation warnings, but found %d warnings: %s",
              warnings.size(), warnings
      ));
    }
  }

  protected Policy validCustomPolicy() {
    Policy customPolicy = new Policy();
    customPolicy.setId("id");
    customPolicy.setSpuri("spuri");
    customPolicy.setQualifier(ObjectIdentifierQualifier.OID_AS_URN);
    customPolicy.setDigestValue("some".getBytes(StandardCharsets.UTF_8));
    customPolicy.setDigestAlgorithm(eu.europa.esig.dss.enumerations.DigestAlgorithm.SHA512);
    return customPolicy;
  }
}
