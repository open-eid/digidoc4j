package org.digidoc4j.impl.bdoc.asic;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.manifest.ManifestValidator;
import org.digidoc4j.test.util.TestDigiDoc4JUtil;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import eu.europa.esig.dss.MimeType;

/**
 * Created by Andrei on 15.11.2017.
 */

public class AsicSContainerTest extends AbstractTest {

  @Test
  @Ignore //FIXME
  public void testAsicSContainer() throws IOException {
    Container container = this.createNonEmptyContainer(Container.DocumentType.ASICS, 1);
    this.createSignatureBy(container, this.pkcs12SignatureToken);
    String file = Paths.get(this.testFolder.getRoot().getPath(), "testasics.asics").toString();
    container.saveAsFile(file);
    SignatureValidationResult result = container.validate();
    Assert.assertTrue(result.isValid());
    ZipFile zipFile = new ZipFile(file);
    ZipEntry mimeTypeEntry = zipFile.getEntry(ManifestValidator.MIMETYPE_PATH);
    ZipEntry manifestEntry = zipFile.getEntry(ManifestValidator.MANIFEST_PATH);
    Assert.assertNotNull(mimeTypeEntry);
    Assert.assertNotNull(manifestEntry);
    String mimeTypeContent = this.getFileContent(zipFile.getInputStream(mimeTypeEntry));
    Assert.assertTrue(mimeTypeContent.contains(MimeType.ASICS.getMimeTypeString()));
    String manifestContent = this.getFileContent(zipFile.getInputStream(manifestEntry));
    Assert.assertTrue(manifestContent.contains(MimeType.ASICS.getMimeTypeString()));
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAsicSContainerTwoFiles() throws IOException {
    this.createSignatureBy(this.createNonEmptyContainer(Container.DocumentType.ASICS, 2), this.pkcs12SignatureToken);
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromPath() throws IOException {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS)
        .fromExistingFile("src/test/resources/testFiles/valid-containers/testasics.asics").build();
    //cannot add second file to existing container
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromZIPPath() throws IOException {
    Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).
        fromExistingFile("src/test/resources/testFiles/valid-containers/testasics.zip").build();
    //cannot add second file to existing container
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromStream() throws IOException {
    try (InputStream stream = new FileInputStream(new File("src/test/resources/testFiles/valid-containers/testasics.asics"))) {
      Container container = ContainerBuilder.aContainer(Container.DocumentType.ASICS).fromStream(stream).build();
      //cannot add second file to existing container
      container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    }
  }

  @Test
  public void createsContainerWithTypeSettingASICS() throws Exception {
    String fileName = this.getFileBy("asics");
    String[] parameters = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    TestDigiDoc4JUtil.call(parameters);
    ZipFile zipFile = new ZipFile(fileName);
    ZipEntry mimeTypeEntry = zipFile.getEntry(ManifestValidator.MIMETYPE_PATH);
    ZipEntry manifestEntry = zipFile.getEntry(ManifestValidator.MANIFEST_PATH);
    Assert.assertNotNull(mimeTypeEntry);
    Assert.assertNotNull(manifestEntry);
    String mimeTypeContent = this.getFileContent(zipFile.getInputStream(mimeTypeEntry));
    Assert.assertTrue(mimeTypeContent.contains(MimeType.ASICS.getMimeTypeString()));
    String manifestContent = this.getFileContent(zipFile.getInputStream(manifestEntry));
    Assert.assertTrue(manifestContent.contains(MimeType.ASICS.getMimeTypeString()));
    Container container = ContainerOpener.open(fileName);
    Assert.assertEquals("ASICS", container.getType());
  }

  @Test
  public void createsContainerWithExtensionASICS() throws Exception {
    String fileName = this.getFileBy("asics");
    String[] parameters = new String[]{"-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};
    TestDigiDoc4JUtil.call(parameters);
    ZipFile zipFile = new ZipFile(fileName);
    ZipEntry mimeTypeEntry = zipFile.getEntry(ManifestValidator.MIMETYPE_PATH);
    ZipEntry manifestEntry = zipFile.getEntry(ManifestValidator.MANIFEST_PATH);
    Assert.assertNotNull(mimeTypeEntry);
    Assert.assertNotNull(manifestEntry);
    String mimeTypeContent = getFileContent(zipFile.getInputStream(mimeTypeEntry));
    Assert.assertTrue(mimeTypeContent.contains(MimeType.ASICS.getMimeTypeString()));
    String manifestContent = getFileContent(zipFile.getInputStream(manifestEntry));
    Assert.assertTrue(manifestContent.contains(MimeType.ASICS.getMimeTypeString()));
    Container container = ContainerOpener.open(fileName);
    Assert.assertEquals("ASICS", container.getType());
  }

}
