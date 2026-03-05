/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.ddoc;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.DigestDataFile;
import org.digidoc4j.ddoc.DigiDocException;
import org.digidoc4j.ddoc.SignedDoc;
import org.digidoc4j.ddoc.utils.ConfigManager;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.test.MockConfigManagerInitializer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DDocFacadeTest extends AbstractTest {

  @Test
  void testSaveThrowsException() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    assertThrows(
            DigiDoc4JException.class,
            () -> facade.save("/not/existing/path/testSaveThrowsException.ddoc")
    );
  }

  @Test
  void testGetDataFileSize() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    DataFile dataFile = facade.getDataFiles().get(0);
    assertEquals(16, dataFile.getFileSize());
  }

  @Test
  void testGetHashCodeDataFile() {
    ConfigManager.init("src/test/resources/testFiles/yaml-configurations/digidoc_test_conf_hashcode_mode.yaml");
    DDocFacade facade = openDDocFacade("src/test/resources/prodFiles/valid-containers/DIGIDOC-XML1.3_hashcode.ddoc");
    DigestDataFile dataFile = (DigestDataFile) facade.getDataFiles().get(0);
    assertEquals("Glitter-rock-4_gallery.jpg", dataFile.getName());
    assertEquals("HASHCODE", dataFile.getContentType());
    ConfigManager.init(Configuration.getInstance().getDDoc4JConfiguration());
  }

  @Test
  void testRemoveDuplicatesExceptions() {
    DDocFacade facade = openDDocFacade("src/test/resources/prodFiles/invalid-containers/23060-1.ddoc");
    ContainerValidationResult result = facade.validate(new Date());
    assertEquals(1, result.getContainerErrors().size());
    assertEquals(21, result.getContainerErrors().get(0).getErrorCode());
    assertEquals("Invalid digest length", result.getContainerErrors().get(0).getMessage());
    assertEquals(2, result.getErrors().size());
    assertEquals(21, result.getErrors().get(0).getErrorCode());
    assertEquals("Invalid digest length", result.getErrors().get(0).getMessage());
    assertEquals(79, result.getErrors().get(1).getErrorCode());
    assertEquals("Bad digest for SignedProperties: S0-SignedProperties", result.getErrors().get(1).getMessage());
  }

  @Test
  void testValidateNoDuplicateExceptions() {
    DDocFacade facade = openDDocFacade("src/test/resources/prodFiles/invalid-containers/Belgia_kandeavaldus_LIV.ddoc");
    ContainerValidationResult result = facade.validate(new Date());
    assertEquals(3, result.getErrors().size());
  }

  @Test
  void testCountDataFiles() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    assertEquals(1, facade.countDataFiles());
  }

  @Test
  void testGetFormat() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    assertEquals("DIGIDOC-XML", facade.getFormat());
  }

  @Test
  void testGetFileId() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    List<org.digidoc4j.DataFile> dataFiles = facade.getDataFiles();
    assertEquals("D0", dataFiles.get(0).getId());
    assertEquals("test.txt", dataFiles.get(0).getName());
  }

  @Test
  void emptyContainerThrowsException() {
    assertThrows(
            DigiDoc4JException.class, 
            () -> openDDocFacade("src/test/resources/testFiles/valid-containers/empty_container_no_signature.ddoc")
    );
  }

  @Test
  void containerWithFileNameThrowsException() {
    assertThrows(
            DigiDoc4JException.class,
            () -> openDDocFacade("file_not_exists")
    );
  }

  @Test
  void savesToStream() throws IOException {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      facade.save(out);
      assertTrue(out.size() != 0);
    }
  }

  @Test
  void savesToStreamThrowsException() throws Exception {
    SignedDoc ddoc = Mockito.mock(SignedDoc.class);
    DigiDocException testException = new DigiDocException(100, "testException", new Throwable("test Exception"));
    Mockito.doThrow(testException).when(ddoc).writeToStream(ArgumentMatchers.any(OutputStream.class));
    DDocFacade facade = new DDocFacade(ddoc);
    try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      assertThrows(
              DigiDoc4JException.class,
              () -> facade.save(out)
      );
    }
  }

  @Test
  void openFromStreamThrowsException() throws IOException {
    FileInputStream stream = new FileInputStream("src/test/resources/testFiles/helper-files/test.txt");
    stream.close();
    assertThrows(
            DigiDoc4JException.class,
            () -> new DDocOpener().open(stream)
    );
  }

  @Test
  void ddocStreamOpener() throws IOException {
    try (FileInputStream stream = new FileInputStream(
            "src/test/resources/testFiles/valid-containers/ddoc_wo_x509IssueName_xmlns.ddoc")) {
      DDocContainer container = new DDocOpener().open(stream);
      assertTrue(container.validate().isValid());
    }
  }

  @Test
  void getSignatureByIndex() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    assertEquals("497c5a2bfa9361a8534fbed9f48e7a12", facade.getSignatures().get(0).getSigningCertificate().getSerial());
  }

  @Test
  void getSignatureWhenNotSigned() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/invalid-containers/signature_without_last_certificate.ddoc");
    assertTrue(facade.getSignatures().isEmpty());
  }

  @Test
  void testCountSignatures() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    assertEquals(1, facade.countSignatures());
  }

  @Test
  void getVersion() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    assertEquals("1.3", facade.getVersion());
  }

  @Test
  void addingDataFileThrowsException() {
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    Container container = new DDocContainer(facade);
    assertThrows(
            NotSupportedException.class,
            () -> container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain")
    );
  }

  @Test
  void configManagerShouldBeInitializedOnlyOnce() {
    DDocFacade.configManagerInitializer = new MockConfigManagerInitializer();
    assertFalse(ConfigManagerInitializer.isConfigManagerInitialized());
    assertEquals(0, MockConfigManagerInitializer.configManagerCallCount);
    openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    assertTrue(ConfigManagerInitializer.isConfigManagerInitialized());
    assertEquals(1, MockConfigManagerInitializer.configManagerCallCount);
    DDocFacade facade = openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    assertTrue(ConfigManagerInitializer.isConfigManagerInitialized());
    assertEquals(1, MockConfigManagerInitializer.configManagerCallCount);
    openDDocFacade("src/test/resources/testFiles/valid-containers/ddoc_for_testing.ddoc");
    assertTrue(ConfigManagerInitializer.isConfigManagerInitialized());
    assertEquals(1, MockConfigManagerInitializer.configManagerCallCount);
  }

  @Test
  void dataFileNamesArePathEscaped() {
    DDocContainer ddocContainer = new DDocOpener().open("src/test/resources/testFiles/invalid-containers/allakirjutatud.fail.ddoc");
    SignedDoc signedDoc = ddocContainer.getDDoc4JFacade().ddoc;
    List<org.digidoc4j.ddoc.DataFile> dataFilesFromSignedDoc = signedDoc.getDataFiles();
    List<DataFile> dataFilesFromFacade = ddocContainer.getDDoc4JFacade().getDataFiles();

    assertSame(dataFilesFromSignedDoc.size(), dataFilesFromFacade.size());

    assertEquals(dataFilesFromSignedDoc.get(0).getFileName(), dataFilesFromFacade.get(0).getName());

    assertEquals("..\\ryndefail1.txt", dataFilesFromSignedDoc.get(1).getFileName());
    assertEquals("ryndefail1.txt", dataFilesFromFacade.get(1).getName());

    assertEquals("..\\..\\ryndefail2.txt", dataFilesFromSignedDoc.get(2).getFileName());
    assertEquals("ryndefail2.txt", dataFilesFromFacade.get(2).getName());

    assertEquals("..\\..\\..\\ryndefail3.txt", dataFilesFromSignedDoc.get(3).getFileName());
    assertEquals("ryndefail3.txt", dataFilesFromFacade.get(3).getName());

    assertEquals("..\\..\\..\\..\\Videos\\ryndefail4.txt", dataFilesFromSignedDoc.get(4).getFileName());
    assertEquals("ryndefail4.txt", dataFilesFromFacade.get(4).getName());
  }

  @Test
  void skXmlDataFilesAreRetrievableWhenMemoryCachingIsConfigured() {
    configuration.setMaxFileSizeCachedInMemoryInMB(-1);
    DDocFacade facade = openDDocFacade("src/test/resources/prodFiles/valid-containers/SK-XML1.0.ddoc");
    assertEquals("Tartu ja Tallinna koostooleping.doc", facade.getDataFiles().get(0).getName());
  }

  /*
   * RESTRICTED METHODS
   */

  private DDocFacade openDDocFacade(String path) {
    return new DDocOpener().open(path).getDDoc4JFacade();
  }

  @BeforeEach
  public void beforeMethod() {
    configuration = Configuration.of(Configuration.Mode.PROD);
    ConfigManagerInitializer.forceInitConfigManager(configuration);
  }

}
