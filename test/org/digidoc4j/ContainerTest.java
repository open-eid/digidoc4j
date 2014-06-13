package org.digidoc4j;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.List;

import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.utils.Helper;
import org.digidoc4j.utils.PKCS12Signer;
import org.junit.Ignore;
import org.junit.Test;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ContainerTest {
  @Test
  public void testAddOneFileToContainerForBDoc() throws Exception {
    Container bDocContainer = new Container();
    bDocContainer.addDataFile("test.txt", "text/plain");
    List<DataFile> dataFiles = bDocContainer.getDataFiles();
    assertEquals(1, dataFiles.size());
    assertEquals(new File("test.txt").getAbsolutePath(), dataFiles.get(0).getFileName());
    assertEquals("text/plain", dataFiles.get(0).getMediaType());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testAddDataFileFromInputStreamToContainerForBDoc() throws Exception {
    Container container = new Container();
    container.addDataFile(new ByteArrayInputStream(new byte[]{0x41}), "test.txt", "text/plain");
  }

  @Test
  public void testRemovesOneFileFromContainerWhenFileExistsForBDoc() throws Exception {
    Container bDocContainer = new Container();
    bDocContainer.addDataFile("test.txt", "text/plain");
    bDocContainer.removeDataFile("test.txt");
    assertEquals(0, bDocContainer.getDataFiles().size());
  }

  @Test
  @Ignore("Not working in Ubuntu check later when jDigiDoc is implemented.")
  public void testCreateAsicContainerSpecifiedByDocumentTypeForBDoc() throws Exception {
    Container asicContainer = new Container(Container.DocumentType.ASIC);
    asicContainer.addDataFile("test.txt", "text/plain");
    asicContainer.sign(new PKCS12Signer("signout.p12", "test"));
    asicContainer.save("test.bdoc");
    assertTrue(Helper.isZipFile(new File("test.bdoc")));
  }

  @Test
  public void testCreateDDocContainer() throws Exception {
    Container dDocContainer = new Container(Container.DocumentType.DDOC);
    dDocContainer.addDataFile("test.txt", "text/plain");
    dDocContainer.sign(new PKCS12Signer("signout.p12", "test"));
    dDocContainer.save("test.ddoc");
    assertTrue(Helper.isXMLFile(new File("test.ddoc")));
  }

  @Test
  public void testAddOneFileToContainerForDDoc() throws Exception {
    Container container = new Container(ContainerInterface.DocumentType.DDOC);
    container.addDataFile("test.txt", "text/plain");
    List<DataFile> dataFiles = container.getDataFiles();
    assertEquals(1, dataFiles.size());
    assertEquals(new File("test.txt").getAbsolutePath(), dataFiles.get(0).getFileName());
    assertEquals("text/plain", dataFiles.get(0).getMediaType());
  }

  @Test
  public void testRemovesOneFileFromContainerWhenFileExistsForDDoc() throws Exception {
    Container container1 = new Container(ContainerInterface.DocumentType.DDOC);
    container1.addDataFile("test.txt", "text/plain");
    Container container = container1;
    container.removeDataFile("test.txt");
    assertEquals(0, container.getDataFiles().size());
  }

  @Test
  public void testOpenCreatedDDocFile() throws Exception {
    Container container1 = new Container(ContainerInterface.DocumentType.DDOC);
    container1.addDataFile("test.txt", "text/plain");
    Container container = container1;
    container.save("testOpenCreatedDDocFile.ddoc");
    Container containerForReading = new Container("testOpenCreatedDDocFile.ddoc");
    assertEquals(ContainerInterface.DocumentType.DDOC, containerForReading.getDocumentType());
    assertEquals(1, container.getDataFiles().size());
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenInvalidFileThrowsException() {
    new Container("test.txt");
  }

  @Test(expected = DigiDoc4JException.class)
  public void testOpenNotExistingFileThrowsException() {
    new Container("noFile.ddoc");
  }

  @Test
  public void testAddFileFromStreamToDDoc() {
    Container container = new Container(ContainerInterface.DocumentType.DDOC);
    container.addDataFile(new ByteArrayInputStream(new byte[]{0x42}), "testFromStream.txt", "text/plain");
    DataFile dataFile = container.getDataFiles().get(0);
    assertEquals("testFromStream.txt", dataFile.getFileName());
  }

  @Test
  public void testGetSignatureFromDDoc() {
    Container container = new Container(ContainerInterface.DocumentType.DDOC);
    container.addDataFile("test.txt", "text/plain");
    container.sign(new PKCS12Signer("signout.p12", "test"));
    List<Signature> signatures = container.getSignatures();
    assertEquals(1, signatures.size());
  }

  public void testSigningWithSignerInfo() throws Exception {
    String city = "myCity";
    String stateOrProvince = "myStateOrProvince";
    String postalCode = "myPostalCode";
    String country = "myCountry";
    String signerRoles = "myRole / myResolution";

    PKCS12Signer signer = new PKCS12Signer("signout.p12", "test");
    signer.setSignatureProductionPlace(city, stateOrProvince, postalCode, country);
    signer.setSignerRoles(asList(signerRoles));

    Container bDocContainer = new Container();
    bDocContainer.addDataFile("test.txt", "text/plain");
    Signature signature = bDocContainer.sign(signer);
  }

  public void testSigningWithOnlyLocationInfo() throws Exception {
  }

  public void testSigningWithPartialSignerInfo() throws Exception {
  }

  public void testSigningWithOnlySignerRole() throws Exception {
  }
}


