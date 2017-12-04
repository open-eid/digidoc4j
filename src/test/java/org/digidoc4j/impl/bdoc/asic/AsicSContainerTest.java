package org.digidoc4j.impl.bdoc.asic;

import static org.digidoc4j.testutils.TestDataBuilder.signContainer;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import eu.europa.esig.dss.MimeType;

import org.apache.commons.io.FileUtils;
import org.digidoc4j.Constant;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.DigiDoc4JTestHelper;
import org.digidoc4j.impl.asic.manifest.ManifestValidator;

import org.junit.After;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Created by Andrei on 15.11.2017.
 */
public class AsicSContainerTest extends DigiDoc4JTestHelper {

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();

  @After
  public void cleanUp() {
    testFolder.delete();
  }

  @Ignore // TODO: Fix this test!
  @Test
  public void testAsicSContainer()throws IOException{
    Container container = createContainerWithFile(testFolder, 1);
    signContainer(container);
    container.saveAsFile("src/test/resources/testFiles/tmp/testasics.asics");
    ValidationResult result = container.validate();

    assertTrue(result.isValid());

    ZipFile zipFile = new ZipFile("src/test/resources/testFiles/tmp/testasics.asics");
    ZipEntry mimeTypeEntry = zipFile.getEntry(ManifestValidator.MIMETYPE_PATH);
    ZipEntry manifestEntry = zipFile.getEntry(ManifestValidator.MANIFEST_PATH);

    assertNotNull(mimeTypeEntry);
    assertNotNull(manifestEntry);

    String mimeTypeContent = getTxtFiles(zipFile.getInputStream(mimeTypeEntry));
    Assert.assertTrue(mimeTypeContent.contains(MimeType.ASICS.getMimeTypeString()));
    String manifestContent = getTxtFiles(zipFile.getInputStream(manifestEntry));
    Assert.assertTrue(manifestContent.contains(MimeType.ASICS.getMimeTypeString()));
  }

  @Test(expected = DigiDoc4JException.class)
  public void testAsicSContainerTwoFiles()throws IOException{
    Container container = createContainerWithFile(testFolder, 2);
    signContainer(container);
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromPath()throws IOException{
    Container container = ContainerBuilder.
        aContainer(Constant.ASICS_CONTAINER_TYPE).
        fromExistingFile("testFiles\\valid-containers\\testasics.asics").
        build();
    //cannot add second file to existing container
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromZIPPath()throws IOException{
    Container container = ContainerBuilder.
        aContainer(Constant.ASICS_CONTAINER_TYPE).
        fromExistingFile("src\\test\\resources\\testFiles\\valid-containers\\testasics.zip").
        build();
    //cannot add second file to existing container
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testExistingAsicSContainerFromStream()throws IOException{
    InputStream inputStream = new FileInputStream(new File("src\\test\\resources\\testFiles\\valid-containers\\testasics.asics"));
    Container container = ContainerBuilder.
        aContainer(Constant.ASICS_CONTAINER_TYPE).
        fromStream(inputStream).
        build();
    //cannot add second file to existing container
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test
  public void createsContainerWithTypeSettingASICS() throws Exception {
    String fileName = testFolder.getRoot().getPath() + "\\test1.asics";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-type", "ASICS", "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    ZipFile zipFile = new ZipFile(fileName);
    ZipEntry mimeTypeEntry = zipFile.getEntry(ManifestValidator.MIMETYPE_PATH);
    ZipEntry manifestEntry = zipFile.getEntry(ManifestValidator.MANIFEST_PATH);

    assertNotNull(mimeTypeEntry);
    assertNotNull(manifestEntry);

    String mimeTypeContent = getTxtFiles(zipFile.getInputStream(mimeTypeEntry));
    Assert.assertTrue(mimeTypeContent.contains(MimeType.ASICS.getMimeTypeString()));
    String manifestContent = getTxtFiles(zipFile.getInputStream(manifestEntry));
    Assert.assertTrue(manifestContent.contains(MimeType.ASICS.getMimeTypeString()));

    Container container = ContainerOpener.open(fileName);
    assertEquals("ASICS", container.getType());
  }

  @Test
  public void createsContainerWithExtensionASICS() throws Exception {
    String fileName = testFolder.getRoot().getPath() + "\\test1.asics";
    Files.deleteIfExists(Paths.get(fileName));

    String[] params = new String[]{"-in", fileName, "-add", "src/test/resources/testFiles/helper-files/test.txt",
        "text/plain", "-pkcs12", "src/test/resources/testFiles/p12/signout.p12", "test"};

    callMainWithoutSystemExit(params);

    ZipFile zipFile = new ZipFile(fileName);
    ZipEntry mimeTypeEntry = zipFile.getEntry(ManifestValidator.MIMETYPE_PATH);
    ZipEntry manifestEntry = zipFile.getEntry(ManifestValidator.MANIFEST_PATH);

    assertNotNull(mimeTypeEntry);
    assertNotNull(manifestEntry);

    String mimeTypeContent = getTxtFiles(zipFile.getInputStream(mimeTypeEntry));
    Assert.assertTrue(mimeTypeContent.contains(MimeType.ASICS.getMimeTypeString()));
    String manifestContent = getTxtFiles(zipFile.getInputStream(manifestEntry));
    Assert.assertTrue(manifestContent.contains(MimeType.ASICS.getMimeTypeString()));

    Container container = ContainerOpener.open(fileName);
    assertEquals("ASICS", container.getType());
  }

  private static Container createContainerWithFile(TemporaryFolder testFolder, int filesCount) throws IOException {
    ContainerBuilder containerBuilder = ContainerBuilder
        .aContainer(Constant.ASICS_CONTAINER_TYPE);
    for (int i = 0; i < filesCount; i++){
      containerBuilder.withDataFile(createTestFile(testFolder).getPath(), "text/plain");
    }
    Container container = containerBuilder.build();
    return container;
  }

  public static File createTestFile(TemporaryFolder testFolder) throws IOException {
    File testFile = testFolder.newFile();
    FileUtils.writeStringToFile(testFile, "AbraDabraKadabra", "UTF-8");
    return testFile;
  }

  private  static String getTxtFiles(InputStream in)  {
    BufferedReader reader = new BufferedReader(new InputStreamReader(in));
    String line;
    StringBuilder content = new StringBuilder();
    try {
      while ((line = reader.readLine()) != null) {
        content.append(line);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
    return content.toString();
  }
}
