package org.digidoc4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.impl.ConfigurationSingeltonHolder;
import org.digidoc4j.impl.asic.AsicFileContainerParser;
import org.digidoc4j.impl.asic.AsicParseResult;
import org.digidoc4j.impl.asic.SkDataLoader;
import org.digidoc4j.impl.asic.ocsp.BDocTSOcspSource;
import org.digidoc4j.impl.asic.xades.XadesSigningDssFacade;
import org.digidoc4j.signers.PKCS12SignatureToken;
import org.digidoc4j.test.Refactored;
import org.digidoc4j.testutils.CustomTemporaryFolder;
import org.digidoc4j.testutils.TSLHelper;
import org.digidoc4j.testutils.TestDataBuilder;
import org.digidoc4j.testutils.TestSigningHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.internal.AssumptionViolatedException;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.client.tsp.OnlineTSPSource;

/**
 * @author Janar Rahumeel (CGI Estonia)
 */

public abstract class AbstractTest extends ConfigurationSingeltonHolder {

  protected final PKCS12SignatureToken pkcs12SignatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/signout.p12", "test".toCharArray());
  protected final PKCS12SignatureToken pkcs12EccSignatureToken = new PKCS12SignatureToken("src/test/resources/testFiles/p12/MadDogOY.p12", "test".toCharArray());
  protected Configuration configuration;
  private final Logger log = LoggerFactory.getLogger(AbstractTest.class);

  @Rule
  public TemporaryFolder testFolder = new CustomTemporaryFolder(new File("target"), "tmp");

  @Rule
  public ExpectedException expectedException = ExpectedException.none();

  @Rule
  public TestWatcher watcher = new TestWatcher() {

    private final Logger log = LoggerFactory.getLogger(Refactored.class);
    private long startTimestamp;

    @Override
    protected void starting(Description description) {
      String starting = String.format("Starting <%s.%s>", description.getClassName(), description.getMethodName());
      this.log.info(StringUtils.rightPad("-", starting.length(), '-'));
      this.log.info(starting);
      this.log.info(StringUtils.rightPad("-", starting.length(), '-'));
      this.startTimestamp = System.currentTimeMillis();
    }

    @Override
    protected void succeeded(Description description) {
      long endTimestamp = System.currentTimeMillis();
      this.log.info("Finished <{}.{}> - took <{}> ms", description.getClassName(), description.getMethodName(),
          endTimestamp - this.startTimestamp);
    }

    @Override
    protected void failed(Throwable e, Description description) {
      this.log.error(String.format("Finished <%s.%s> - failed", description.getClassName(), description.getMethodName()), e);
    }

    @Override
    protected void skipped(AssumptionViolatedException e, Description description) {
      String skipped = String.format("Skipped <%s.%s>", description.getClassName(), description.getMethodName());
      this.log.debug(StringUtils.rightPad("-", skipped.length(), '-'));
      this.log.debug(skipped);
      this.log.debug(StringUtils.rightPad("-", skipped.length(), '-'));
    }

  };

  @Before
  public void beforeMethod() {
    this.log.info("NB! Before method --> START");
    ConfigurationSingeltonHolder.reset();
    this.setGlobalMode(Configuration.Mode.TEST);
    this.before();
    this.log.info("NB! Before method --> END");
  }

  @After
  public void afterMethod() {
    this.testFolder.delete(); // TODO doesn't work
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

  protected String getJDigiDocConfigurationValue(String key) {
    return this.configuration.getJDigiDocConfiguration().get(key);
  }

  protected void addCertificateToTSL(Path path, TSLCertificateSource source) {
    try (InputStream stream = new FileInputStream(path.toFile())) {
      source.addTSLCertificate(DSSUtils.loadCertificate(stream).getCertificate());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  protected AsicParseResult getParseResult(Path path) {
    return new AsicFileContainerParser(path.toString(), Configuration.getInstance()).read();
  }

  protected Container openContainer(Path path) {
    return ContainerBuilder.aContainer().fromExistingFile(path.toString()).build();
  }

  protected Container openContainerByConfiguration(Path path) {
    return openContainerByConfiguration(path, this.configuration);
  }

  protected Container openContainerByConfiguration(Path path, Configuration configuration) {
    ContainerBuilder builder = ContainerBuilder.aContainer().fromExistingFile(path.toString());
    if (this.configuration != null) {
      builder.withConfiguration(this.configuration);
    }
    return builder.build();
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

  protected Container createNonEmptyContainerBy(Container.DocumentType type) {
    try {
      return TestDataBuilder.createContainerWithFile(this.testFolder, type, Configuration.Mode.TEST);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  protected Container createNonEmptyContainerBy(Path path) {
    return TestDataBuilder.createContainerWithFile(path.toString());
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
    return String.format("%s/%s.%s", this.testFolder.getRoot().getPath(), RandomUtils.nextInt(), extension);
  }

  protected <T> T createSignatureBy(Container container, SignatureToken signatureToken) {
    return (T) this.createSignatureBy(container, null, signatureToken);
  }

  protected <T> T createSignatureBy(Container container, SignatureProfile signatureProfile, SignatureToken signatureToken) {
    SignatureBuilder builder = SignatureBuilder.aSignature(container).withSignatureToken(signatureToken);
    if (signatureProfile != null) {
      builder.withSignatureProfile(signatureProfile);
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
      SignatureBuilder builder = SignatureBuilder.aSignature(TestDataBuilder.createContainerWithFile(this.testFolder, type, mode));
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

  protected DSSDocument sign(XadesSigningDssFacade facade, DigestAlgorithm digestAlgorithm) {
    return facade.signDocument(TestSigningHelper.sign(this.getDataToSign(facade), digestAlgorithm), this.createDataFilesToSign());
  }

  protected byte[] getDataToSign(XadesSigningDssFacade facade) {
    facade.setSigningCertificate(this.pkcs12SignatureToken.getCertificate());
    return facade.getDataToSign(this.createDataFilesToSign());
  }

  protected List<DataFile> createDataFilesToSign() {
    return Collections.singletonList(new DataFile("src/test/resources/testFiles/helper-files/test.txt", "plain/text"));
  }

  protected void evictTSLCache() {
    TSLHelper.deleteTSLCache();
  }

  protected long getTSLCacheLastModificationTime() {
    return TSLHelper.getCacheLastModificationTime();
  }

  protected boolean isTSLCacheEmpty() {
    return TSLHelper.isTslCacheEmpty();
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

  protected BDocTSOcspSource createOCSPSource() {
    BDocTSOcspSource source = new BDocTSOcspSource(this.configuration);
    SkDataLoader loader = SkDataLoader.createOcspDataLoader(this.configuration);
    loader.setUserAgentSignatureProfile(SignatureProfile.LT);
    source.setDataLoader(loader);
    return source;
  }

  private OnlineTSPSource createTSPSource() {
    SkDataLoader loader = SkDataLoader.createTimestampDataLoader(this.configuration);
    loader.setUserAgentSignatureProfile(SignatureProfile.LT);
    OnlineTSPSource source = new OnlineTSPSource(this.configuration.getTspSource());
    source.setDataLoader(loader);
    return source;
  }

}
