/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.ddoc;

import org.digidoc4j.*;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.ddoc.utils.ConfigManager;
import org.digidoc4j.exceptions.ConfigurationException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.test.MockConfigManagerInitializer;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Matchers;
import org.mockito.Mockito;

import java.io.*;
import java.nio.file.Paths;
import java.util.List;

public class DDocFacadeTest extends AbstractTest {

  @Test(expected = DigiDoc4JException.class)
  public void testSaveThrowsException() throws Exception {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    facade.save("/not/existing/path/testSaveThrowsException.ddoc");
  }

  @Test
  public void testGetDataFileSize() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    DataFile dataFile = facade.getDataFiles().get(0);
    Assert.assertEquals(16, dataFile.getFileSize());
  }

  @Test
  public void testGetHashCodeDataFile() {
    ConfigManager.init("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_hashcode_mode.yaml");
    DDocFacade facade = openDDocFacade("src/test/resources/prodFiles/valid-containers/DIGIDOC-XML1.3_hashcode.ddoc");
    DigestDataFile dataFile = (DigestDataFile) facade.getDataFiles().get(0);
    Assert.assertEquals("Glitter-rock-4_gallery.jpg", dataFile.getName());
    Assert.assertEquals("HASHCODE", dataFile.getContentType());
    ConfigManager.init(Configuration.getInstance().getDDoc4JConfiguration());
  }

  @Test
  public void testRemoveDuplicatesExceptions() {
    DDocFacade facade = openDDocFacade("src/test/resources/prodFiles/invalid-containers/23060-1.ddoc");
    ContainerValidationResult result = facade.validate();
    Assert.assertEquals(1, result.getContainerErrors().size());
    Assert.assertEquals(21, result.getContainerErrors().get(0).getErrorCode());
    Assert.assertEquals("Invalid digest length", result.getContainerErrors().get(0).getMessage());
    Assert.assertEquals(2, result.getErrors().size());
    Assert.assertEquals(21, result.getErrors().get(0).getErrorCode());
    Assert.assertEquals("Invalid digest length", result.getErrors().get(0).getMessage());
    Assert.assertEquals(79, result.getErrors().get(1).getErrorCode());
    Assert.assertEquals("Bad digest for SignedProperties: S0-SignedProperties", result.getErrors().get(1).getMessage());
  }

  @Test
  public void testValidateNoDuplicateExceptions() {
    DDocFacade facade = openDDocFacade("src/test/resources/prodFiles/invalid-containers/Belgia_kandeavaldus_LIV.ddoc");
    ContainerValidationResult result = facade.validate();
    Assert.assertEquals(3, result.getErrors().size());
  }

  @Test
  public void testCountDataFiles() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertEquals(1, facade.countDataFiles());
  }

  @Test
  public void testGetFormat() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertEquals("DIGIDOC-XML", facade.getFormat());
  }

  @Test
  public void testGetFileId() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    List<org.digidoc4j.DataFile> dataFiles = facade.getDataFiles();
    Assert.assertEquals("D0", dataFiles.get(0).getId());
    Assert.assertEquals("test.txt", dataFiles.get(0).getName());
  }

  @Test(expected = DigiDoc4JException.class)
  public void emptyContainerThrowsException() {
    openDDocFacade("src/test/resources/testFiles/valid-containers/empty_container_no_signature.ddoc");
  }

  @Test(expected = DigiDoc4JException.class)
  public void containerWithFileNameThrowsException() throws Exception {
    this.openDDocFacade("file_not_exists");
  }

  @Test
  public void savesToStream() throws IOException {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      facade.save(out);
      Assert.assertTrue(out.size() != 0);
    }
  }

  @Test(expected = DigiDoc4JException.class)
  public void savesToStreamThrowsException() throws Exception {
    SignedDoc ddoc = Mockito.mock(SignedDoc.class);
    DigiDocException testException = new DigiDocException(100, "testException", new Throwable("test Exception"));
    Mockito.doThrow(testException).when(ddoc).writeToStream(Matchers.any(OutputStream.class));
    DDocFacade facade = new DDocFacade(ddoc);
    try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      facade.save(out);
    }
  }

  @Test(expected = DigiDoc4JException.class)
  public void openFromStreamThrowsException() throws IOException {
    FileInputStream stream = new FileInputStream(new File("src/test/resources/testFiles/helper-files/test.txt"));
    stream.close();
    new DDocOpener().open(stream);
  }

  @Test
  public void ddocStreamOpener() throws IOException {
    try (FileInputStream stream = new FileInputStream(
            new File("src/test/resources/testFiles/valid-containers/ddoc_wo_x509IssueName_xmlns.ddoc"))) {
      DDocContainer container = new DDocOpener().open(stream);
      Assert.assertTrue(container.validate().isValid());
    }
  }

  @Test
  public void getSignatureByIndex() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertEquals("497c5a2bfa9361a8534fbed9f48e7a12", facade.getSignature(0).getSigningCertificate().getSerial());
  }

  @Test
  public void getSignatureWhenNotSigned() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/invalid-containers/signature_without_last_certificate.ddoc");
    Assert.assertTrue(facade.getSignatures().isEmpty());
  }

  @Test
  public void testCountSignatures() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertEquals(1, facade.countSignatures());
  }

  @Test
  public void getVersion() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertEquals("1.3", facade.getVersion());
  }

  @Test(expected = NotSupportedException.class)
  public void addingDataFileThrowsException() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Container container = new DDocContainer(facade);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
  }

  @Test
  public void configManagerShouldBeInitializedOnlyOnce() throws Exception {
    DDocFacade.configManagerInitializer = new MockConfigManagerInitializer();
    Assert.assertFalse(ConfigManagerInitializer.isConfigManagerInitialized());
    Assert.assertEquals(0, MockConfigManagerInitializer.configManagerCallCount);
    openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertTrue(ConfigManagerInitializer.isConfigManagerInitialized());
    Assert.assertEquals(1, MockConfigManagerInitializer.configManagerCallCount);
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertTrue(ConfigManagerInitializer.isConfigManagerInitialized());
    Assert.assertEquals(1, MockConfigManagerInitializer.configManagerCallCount);
    this.openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Assert.assertTrue(ConfigManagerInitializer.isConfigManagerInitialized());
    Assert.assertEquals(1, MockConfigManagerInitializer.configManagerCallCount);
  }

  @Test(expected = ConfigurationException.class)
  public void openingDDoc_withoutCAConfiguration_shouldThrowException() throws Exception {
    this.configuration = new Configuration(Configuration.Mode.TEST);
    this.configuration.loadConfiguration("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_no_ca.yaml");
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
    this.openContainerByConfiguration(Paths.get("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc"));
  }

  /*
   * RESTRICTED METHODS
   */

  private DDocFacade openDDocFacade(String path) {
    return new DDocOpener().open(path).getDDoc4JFacade();
  }

  @Before
  public void beforeMethod() {
    this.configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(this.configuration);
  }

}
