package ee.sk.digidoc4j;

import ee.sk.digidoc4j.exceptions.NotYetImplementedException;
import ee.sk.digidoc4j.utils.PKCS12Signer;
import ee.sk.digidoc4j.utils.SignerInformation;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.util.List;

import static org.junit.Assert.assertEquals;

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
  public void testSigningWithSignerInfo() throws Exception {                //TODO MJB currently fails if a parameter is missing. Parameters are optional
    String city = "myCity";
    String stateOrProvince = "myStateOrProvince";
    String postalCode = "myPostalCode";
    String country = "myCountry";
    String signerRoles = "myRole / myResolution";

    SignerInformation signerInformation = new SignerInformation(city, stateOrProvince, postalCode, country, signerRoles);
    Container bDocContainer = new Container();
    bDocContainer.addDataFile("test.txt", "text/plain");
    PKCS12Signer signer = new PKCS12Signer("signout.p12", "test");
    Signature signature = bDocContainer.sign(signer, signerInformation);
//    assertEquals(city, bDocContainer.getSignatures());                     //TODO MJB after Signature implementation and testing add tests here to ensure right values
    System.out.println();
  }
}


