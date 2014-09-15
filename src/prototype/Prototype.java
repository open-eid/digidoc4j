package prototype;

import org.digidoc4j.api.Container;
import org.digidoc4j.api.ValidationResult;
import org.digidoc4j.api.exceptions.DigiDoc4JException;

/**
 * Prototype for testing purposes
 */
public final class Prototype {

  private Prototype() {

  }

  /**
   * Main method
   *
   * @param args command line arguments
   */
  public static void main(String[] args) {
    //System.setProperty("digidoc4j.mode", "TEST");
    //Configuration configuration = new Configuration(Configuration.Mode.TEST);

//    Container container = Container.create();
//    container.setConfiguration(configuration);
//    container.addDataFile("testFiles/test.txt", "text/plain");
//    container.sign(new PKCS12Signer("testFiles/cb_b4b.p12", "c0deb0rne!xp".toCharArray()));
//    container.sign(new PKCS12Signer("testFiles/signout.p12", "test".toCharArray()));
//    container.sign(new PKCS12Signer("testFiles/signout.p12", "test".toCharArray()));
//    container.save("prototype.bdoc");


    Container container1 = Container.open("util/test.bdoc");
//    Container container1 = Container.open("prototype.bdoc", configuration);
    ValidationResult validationResult = container1.validate();
    if (validationResult.hasErrors()) {
      for (DigiDoc4JException error : validationResult.getErrors()) {
        System.out.println(error.getMessage());
      }
    }
  }
}
