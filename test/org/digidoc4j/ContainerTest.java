package org.digidoc4j;

import java.io.*;
import java.util.List;

import org.digidoc4j.exceptions.NotYetImplementedException;
import org.digidoc4j.utils.PKCS12Signer;
import org.junit.Test;

import static java.util.Arrays.asList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ContainerTest {
  @Test
  public void testAddOneFileToContainer() throws Exception {
    Container bDocContainer = new Container();
    bDocContainer.addDataFile("test.txt", "text/plain");
    List<DataFile> dataFiles = bDocContainer.getDataFiles();
    assertEquals(1, dataFiles.size());
    assertEquals("test.txt", dataFiles.get(0).getFileName());
    assertEquals("text/plain", dataFiles.get(0).getMediaType());
  }

  @Test(expected = NotYetImplementedException.class)
  public void testAddDataFileFromInputStreamToContainer() throws Exception {
    Container container = new Container();
    container.addDataFile(new ByteArrayInputStream(new byte[]{0x41}), "test.txt", "text/plain");
  }

  @Test
  public void testRemovesOneFileFromContainerWhenFileExists() throws Exception {
    Container bDocContainer = new Container();
    bDocContainer.addDataFile("test.txt", "text/plain");
    bDocContainer.removeDataFile("test.txt");

    assertEquals(0, bDocContainer.getDataFiles().size());
  }

  @Test
  public void testCreateAsicContainerSpecifiedByDocumentType() throws Exception {
    Container asicContainer = new Container(Container.DocumentType.ASIC);
    asicContainer.addDataFile("test.txt", "text/plain");
    asicContainer.sign(new PKCS12Signer("signout.p12", "test"));
    asicContainer.save("test.zip");
    assertTrue(isZipFile(new File("test.zip")));
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

  private boolean isZipFile(File file) throws IOException {
    DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(file)));
    int test = in.readInt();
    in.close();
    return test == 0x504b0304;
  }
}


