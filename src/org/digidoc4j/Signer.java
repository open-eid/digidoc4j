package org.digidoc4j;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Abstract class providing signing interface
 */
public abstract class Signer {
  final Logger logger = LoggerFactory.getLogger(Signer.class);
  private SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
  private List<String> signerRoles = new ArrayList<>();

  /**
   * Returns signer certificate
   *
   * @return signer certificate
   */
  public abstract X509Certificate getCertificate();

  /**
   * Returns signature production city
   *
   * @return signing city
   */
  public final String getCity() {
    logger.debug("");
    return signatureProductionPlace.getCity();
  }

  /**
   * Returns signature production country
   *
   * @return signing country
   */
  public final String getCountry() {
    logger.debug("");
    return signatureProductionPlace.getCountry();
  }

  /**
   * Returns signature production place postal code
   *
   * @return postal code
   */

  public final String getPostalCode() {
    logger.debug("");
    return signatureProductionPlace.getPostalCode();
  }

  //TODO this is not good way to pass so many parameters discuss it with SK

  /**
   * Sets Signature production place
   *
   * @param city            city
   * @param stateOrProvince state or province
   * @param postalCode      postal code
   * @param country         country
   */
  public void setSignatureProductionPlace(final String city, final String stateOrProvince, final String postalCode,
                                          final String country) {
    logger.debug("");
    signatureProductionPlace.setCity(city);
    signatureProductionPlace.setStateOrProvince(stateOrProvince);
    signatureProductionPlace.setPostalCode(postalCode);
    signatureProductionPlace.setCountry(country);
  }

  /**
   * Sets signature production place
   *
   * @param signatureProductionPlace signature production place
   */
  public void setSignatureProductionPlace(SignatureProductionPlace signatureProductionPlace) {
    logger.debug("");
    this.signatureProductionPlace = signatureProductionPlace;
  }


  /**
   * Returns signature production state or province
   *
   * @return state or province
   */
  public final String getStateOrProvince() {
    logger.debug("");
    return signatureProductionPlace.getStateOrProvince();
  }

  /**
   * Returns signer roles as list. If no roles are defined returns empty list.
   *
   * @return signer roles
   */
  public final List<String> getSignerRoles() {
    logger.debug("");
    return signerRoles;
  }

  /**
   * Sets signer roles as list of strings
   *
   * @param signerRoles signer roles
   */
  public void setSignerRoles(final List<String> signerRoles) {
    logger.debug("");
    this.signerRoles = signerRoles;
  }

  /**
   * Returns signature production place
   *
   * @return signature production place
   */
  public SignatureProductionPlace getSignatureProductionPlace() {
    logger.debug("");
    return signatureProductionPlace;
  }

  /**
   * Retrieves private key
   *
   * @return private key
   */
  public abstract PrivateKey getPrivateKey();

  /**
   * There must be implemented routines needed for signing
   *
   * @param container  provides needed information for signing
   * @param dataToSign data to sign
   * @return signature raw value
   */
  public abstract byte[] sign(Container container, byte[] dataToSign);


  /**
   * Calculates digest for data with hash algorithm provided by container
   *
   * @param container provides needed information for digesting
   * @param data      data to hash
   * @return digest calculated over data
   */
  public static byte[] calculateDigest(Container container, byte[] data) {
    org.digidoc4j.DigestAlgorithm digestAlgorithm = container.getDigestAlgorithm();
    return DSSUtils.digest(DigestAlgorithm.forXML(digestAlgorithm.toString()), data);
  }
}
