package org.digidoc4j;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.impl.CommonOCSPSource;
import org.digidoc4j.impl.ConfigurationSingeltonHolder;
import org.digidoc4j.impl.asic.AsicFileContainerParser;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.AsicStreamContainerParser;
import org.digidoc4j.impl.asic.SkDataLoader;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import static org.digidoc4j.Container.DocumentType.ASICE;
import static org.digidoc4j.Container.DocumentType.ASICS;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.digidoc4j.Container.DocumentType.DDOC;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public abstract class AbstractTest extends ConfigurationSingeltonHolder {

  private static final Logger LOGGER = LoggerFactory.getLogger(AbstractTest.class);

  protected static final String BDOC_WITH_TM_SIG = "src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc";
  protected static final String BDOC_WITH_TM_AND_TS_SIG = "src/test/resources/testFiles/valid-containers/bdoc-with-tm-and-ts-signature.bdoc";
  protected static final String BDOC_WITH_B_EPES_SIG = "src/test/resources/testFiles/valid-containers/bdoc-with-b-epes-signature.bdoc";
  protected static final String ASIC_WITH_NO_SIG = "src/test/resources/testFiles/valid-containers/container_without_signatures.bdoc";
  protected static final String ASICE_WITH_TS_SIG_BUT_BDOC_EXTENSION = "src/test/resources/testFiles/valid-containers/one_signature.bdoc";
  protected static final String ASICE_WITH_TS_SIG = "src/test/resources/testFiles/valid-containers/valid-asice.asice";
  protected static final String DDOC_TEST_FILE = "src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc";

  protected final PKCS12SignatureToken pkcs12SignatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/signout.p12", "test".toCharArray());
  protected final PKCS12SignatureToken pkcs12EccSignatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/MadDogOY.p12", "test".toCharArray());
  protected final PKCS12SignatureToken pkcs12Esteid2018SignatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/sign_ESTEID2018.p12", "1234".toCharArray());
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

  protected <T> T createEmptyContainer() {
    return (T) ContainerBuilder.aContainer().build();
  }

  protected <T> T createEmptyContainer(Class<T> clazz) {
    return (T) ContainerBuilder.aContainer().build();
  }

  protected <T> T createEmptyContainerBy(Container.DocumentType type) {
    return (T) ContainerBuilder.aContainer(type).build();
  }

  protected <T> T createEmptyContainerBy(Container.DocumentType type, Class<T> clazz) {
    return (T) ContainerBuilder.aContainer(type).build();
  }

  protected Container createNonEmptyContainer() {
    return this.createNonEmptyContainerBy(Container.DocumentType.BDOC);
  }

  protected Container createNonEmptyContainerByConfiguration() {
    return ContainerBuilder.aContainer().withConfiguration(this.configuration)
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
      return IOUtils.toString(stream, "UTF-8");
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

  protected <T> T createSignatureBy(Container container, SignatureToken signatureToken) {
    return (T) this.createSignatureBy(container, (SignatureProfile) null, signatureToken);
  }

  protected <T> T createSignatureBy(Container container, DigestAlgorithm digestAlgorithm, SignatureToken signatureToken) {
    return this.createSignatureBy(container, null, digestAlgorithm, signatureToken);
  }

  protected <T> T createSignatureBy(Container container, SignatureProfile signatureProfile, SignatureToken signatureToken) {
    return this.createSignatureBy(container, signatureProfile, null, signatureToken);
  }

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
    return (T) this.createSignatureBy(type, null, signatureToken, Configuration.Mode.TEST);
  }

  protected <T> T createSignatureBy(Container.DocumentType type, SignatureToken signatureToken, Class<T> clazz) {
    return (T) this.createSignatureBy(type, null, signatureToken, Configuration.Mode.TEST);
  }

  protected <T> T createSignatureBy(Container.DocumentType type, SignatureToken signatureToken, Configuration.Mode mode) {
    return (T) this.createSignatureBy(type, null, signatureToken, mode);
  }

  protected <T> T createSignatureBy(Container.DocumentType type, SignatureProfile signatureProfile, SignatureToken signatureToken) {
    return (T) this.createSignatureBy(type, signatureProfile, signatureToken, Configuration.Mode.TEST);
  }

  protected <T> T createSignatureBy(Container.DocumentType type, SignatureProfile signatureProfile, SignatureToken signatureToken, Configuration.Mode mode) {
    try {
      SignatureBuilder builder = SignatureBuilder.aSignature(TestDataBuilderUtil.createContainerWithFile(this.testFolder, type, mode));
      if (signatureProfile != null) {
        builder.withSignatureProfile(signatureProfile);
      }
      return (T) builder.withSignatureToken(signatureToken).invokeSigning();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  protected <T> T createSignatureBy(DigestAlgorithm digestAlgorithm, SignatureToken signatureToken) {
    try {
      return (T) SignatureBuilder.aSignature(this.createNonEmptyContainer()).withSignatureDigestAlgorithm(digestAlgorithm).
          withSignatureToken(signatureToken).invokeSigning();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  protected String createSignedContainerBy(String extension) {
    String file = this.getFileBy(extension);
    Container container = this.createNonEmptyContainerBy(Paths.get("src/test/resources/testFiles/helper-files/test.txt"), "text/plain");
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    container.save(file);
    return file;
  }

  protected String createNonEmptyLargeContainer(long size) {
    String fileName = this.getFileBy("bdoc");
    try {
      RandomAccessFile largeFile = new RandomAccessFile(fileName, "rw");
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
    return this.pkcs12SignatureToken.sign(digestAlgorithm, dataToSign);
  }

  protected byte[] getDataToSign(XadesSigningDssFacade facade) {
    facade.setSigningCertificate(this.pkcs12SignatureToken.getCertificate());
    return facade.getDataToSign(this.createDataFilesToSign());
  }

  protected List<DataFile> createDataFilesToSign() {
    return Collections.singletonList(new DataFile("src/test/resources/testFiles/helper-files/test.txt", "plain/text"));
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

  protected X509Certificate openX509Certificate(Path path) {
    try {
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      try (FileInputStream stream = new FileInputStream(path.toFile())) {
        return (X509Certificate) certificateFactory.generateCertificate(stream);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  protected XadesSigningDssFacade createSigningFacade() {
    XadesSigningDssFacade facade = new XadesSigningDssFacade();
    facade.setCertificateSource(this.configuration.getTSL());
    facade.setOcspSource(this.createOCSPSource());
    facade.setTspSource(this.createTSPSource());
    return facade;
  }

  protected CommonOCSPSource createOCSPSource() {
    CommonOCSPSource source = new CommonOCSPSource(this.configuration);
    SkDataLoader loader = SkDataLoader.ocsp(this.configuration);
    loader.setUserAgent(Helper.createBDocUserAgent(SignatureProfile.LT));
    source.setDataLoader(loader);
    return source;
  }

  private OnlineTSPSource createTSPSource() {
    SkDataLoader loader = SkDataLoader.timestamp(this.configuration);
    loader.setUserAgent(Helper.createBDocUserAgent(SignatureProfile.LT));
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

  protected void assertTimestampSignature(Signature signature) {
    Assert.assertNotNull(signature);
    Assert.assertTrue(signature instanceof AsicESignature);
    Assert.assertEquals(SignatureProfile.LT, signature.getProfile());
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

}
