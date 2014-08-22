package prototype;

import ee.sk.utils.ConfigManager;
import org.digidoc4j.ASiCSContainer;
import org.digidoc4j.api.Container;
import org.digidoc4j.api.exceptions.DigiDoc4JException;
import org.digidoc4j.signers.PKCS12Signer;

import java.util.List;

/**
 * Elliptic curve cryptography test
 */
public final class ECCTestMain {
  private ECCTestMain() {

  }

  /**
   * @param args aaa
   */
  public static void main(String[] args) {
    //Configuration configuration = new Configuration(PROD);
    Container container = Container.create(Container.DocumentType.DDOC);
    ConfigManager.instance().setStringProperty("DIGIDOC_PKCS12_CONTAINER", "testFiles/cb_b4b.p12");
    ConfigManager.instance().setStringProperty("DIGIDOC_PKCS12_PASSWD", "c0deb0rne!xp");

    //container.setConfiguration(configuration);
    container.addDataFile("testFiles/test.txt", "text/plain");
    container.sign(new PKCS12Signer("testFiles/cb_b4b.p12", "c0deb0rne!xp"));
    container.save("nonrepbitsigning.ascis");

    List<DigiDoc4JException> exceptions = ((ASiCSContainer) container).verify();
    for (DigiDoc4JException e : exceptions) {
      System.out.println(e.toString());
    }
  }
}
