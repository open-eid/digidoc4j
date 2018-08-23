/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j;

import static java.util.Arrays.asList;
import static org.digidoc4j.Constant.ASICE_CONTAINER_TYPE;
import static org.digidoc4j.Constant.ASICS_CONTAINER_TYPE;
import static org.digidoc4j.Constant.BDOC_CONTAINER_TYPE;
import static org.digidoc4j.Constant.DDOC_CONTAINER_TYPE;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.exceptions.ContainerWithoutFilesException;
import org.digidoc4j.exceptions.NotSupportedException;
import org.digidoc4j.exceptions.SignatureTokenMissingException;
import org.digidoc4j.exceptions.SignerCertificateRequiredException;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.impl.asic.AsicSignatureBuilder;
import org.digidoc4j.impl.asic.asice.AsicESignatureBuilder;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignatureBuilder;
import org.digidoc4j.impl.ddoc.DDocSignatureBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.Policy;

/**
 * <p>Creating signatures on a container.</p>
 * <p>Here's an example of creating a signature:</p>
 * <p><code>
 * {@link Signature} signature = {@link SignatureBuilder}. <br/>
 * &nbsp;&nbsp; {@link SignatureBuilder#aSignature(Container) aSignature(container)}. <br/>
 * &nbsp;&nbsp; {@link SignatureBuilder#withCity(String) withCity("San Pedro")}. <br/>
 * &nbsp;&nbsp; {@link SignatureBuilder#withCountry(String) withCountry("Val Verde")}. <br/>
 * &nbsp;&nbsp; {@link SignatureBuilder#withRoles(String...) withRoles("Manager", "Suspicious Fisherman")}. <br/>
 * &nbsp;&nbsp; {@link SignatureBuilder#withSignatureDigestAlgorithm(DigestAlgorithm) withSignatureDigestAlgorithm(DigestAlgorithm.SHA256)}. // Digest algorithm is SHA-256 <br/>
 * &nbsp;&nbsp; {@link SignatureBuilder#withSignatureProfile(SignatureProfile) withSignatureProfile(SignatureProfile.LT_TM)}. // Signature profile is Time-Mark <br/>
 * &nbsp;&nbsp; {@link SignatureBuilder#withSignatureToken(SignatureToken) withSignatureToken(signatureToken)}. // Use signature token <br/>
 * &nbsp;&nbsp; {@link SignatureBuilder#invokeSigning() invokeSigning()}; // Creates a signature using signature token
 * </code></p>
 * <p>
 * Use {@link SignatureBuilder#aSignature(Container) SignatureBuilder.aSignature(container)} to create a new signature builder,
 * populate the builder with data and then call {@link SignatureBuilder#invokeSigning()} to create a signature on the container
 * using {@link SignatureToken}. Signature token must be provided with {@link SignatureBuilder#withSignatureToken(SignatureToken)}.
 * </p>
 * <p>
 * Use {@link SignatureBuilder#buildDataToSign()} to create {@link DataToSign} object
 * that can be used in external signing (e.g. signing in the Web). To build {@link DataToSign} object, signer certificate
 * must be provided with {@link SignatureBuilder#withSigningCertificate(X509Certificate)}.
 * </p>
 */
public abstract class SignatureBuilder implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(SignatureBuilder.class);
  protected static Map<String, Class<? extends SignatureBuilder>> customSignatureBuilders = new HashMap<>();
  protected static Policy policyDefinedByUser;
  protected SignatureParameters signatureParameters = new SignatureParameters();
  protected SignatureToken signatureToken;
  protected Container container;

  /**
   * Create a new signature builder based on a container.
   * Container is used to determine which type of signature should be created.
   *
   * @param container container to be signed.
   * @return builder for creating a signature.
   */
  public static SignatureBuilder aSignature(Container container) {
    SignatureBuilder builder = createBuilder(container);
    builder.setContainer(container);
    return builder;
  }

  private static SignatureBuilder createBuilder(Container container) {
    String containerType = container.getType();
    if (isCustomContainerType(containerType)) {
      return createCustomSignatureBuilder(containerType);
    } else if (isContainerType(containerType, BDOC_CONTAINER_TYPE)) {
      return new BDocSignatureBuilder();
    } else if (isContainerType(containerType, ASICE_CONTAINER_TYPE)) {
      return new AsicESignatureBuilder();
    } else if (isContainerType(containerType, ASICS_CONTAINER_TYPE)) {
      return new AsicSignatureBuilder();
    } else if (isContainerType(containerType, DDOC_CONTAINER_TYPE)) {
      return new DDocSignatureBuilder();
    } else {
      logger.error("Unknown container type: " + container.getType());
      throw new NotSupportedException("Unknown container type: " + container.getType());
    }
  }

  /**
   * Setting custom signature builder implementation used when creating signatures for the particular container type.
   *
   * @param containerType         container type corresponding to the signature builder.
   * @param signatureBuilderClass signature builder class used for creating signatures for the container type.
   * @param <T>                   signature builder class extending {@link SignatureBuilder}.
   */
  public static <T extends SignatureBuilder> void setSignatureBuilderForContainerType(
      String containerType,
      Class<T> signatureBuilderClass) {
    customSignatureBuilders.put(containerType, signatureBuilderClass);
  }

  /**
   * Clears all custom signature builders to use only default signature builders.
   */
  public static void removeCustomSignatureBuilders() {
    customSignatureBuilders.clear();
  }

  private static boolean isCustomContainerType(String containerType) {
    return customSignatureBuilders.containsKey(containerType);
  }

  private static boolean isContainerType(String containerType, String ddocContainerType) {
    return StringUtils.equalsIgnoreCase(ddocContainerType, containerType);
  }

  private static SignatureBuilder createCustomSignatureBuilder(String containerType) {
    Class<? extends SignatureBuilder> builderClass = customSignatureBuilders.get(containerType);
    try {
      logger.debug("Instantiating signature builder class " +
          builderClass.getName() + " for container type " + containerType);
      return builderClass.newInstance();
    } catch (ReflectiveOperationException e) {
      logger.error("Unable to instantiate custom signature builder class " +
          builderClass.getName() + " for type " + containerType);
      throw new TechnicalException("Unable to instantiate custom signature builder class " +
          builderClass.getName() + " for type " + containerType, e);
    }
  }

  protected static boolean isDefinedAllPolicyValues() {
    return StringUtils.isNotBlank(policyDefinedByUser.getId())
        && policyDefinedByUser.getDigestValue() != null
        && StringUtils.isNotBlank(policyDefinedByUser.getQualifier())
        && policyDefinedByUser.getDigestAlgorithm() != null
        && StringUtils.isNotBlank(policyDefinedByUser.getSpuri());
  }

  /**
   * Invokes a signing process on the container with a signature token (See {@link SignatureToken}).
   * Signature token must be provided with {@link SignatureBuilder#withSignatureToken}.
   *
   * @return a new signature on the container.
   * @throws SignatureTokenMissingException if signature token is not provided with {@link SignatureBuilder#withSignatureToken}
   * @see SignatureToken
   */
  public Signature invokeSigning() throws SignatureTokenMissingException {
    if (signatureToken == null) {
      logger.error("Cannot invoke signing without signature token. Add 'withSignatureToken()' method call or call 'buildDataToSign() instead.'");
      throw new SignatureTokenMissingException();
    }
    return invokeSigningProcess();
  }

  /**
   * Signing process implementation that is called by {@link SignatureBuilder#invokeSigning()} method.
   * Must be implemented by the class implementing the builder.
   *
   * @return a new signature on the container.
   */
  protected abstract Signature invokeSigningProcess();

  /**
   * Creates data to be signed externally.
   * <p>
   * If the signing process involves signing the container externally (e.g. signing in the Web by a browser plugin),
   * then {@link DataToSign} provides necessary data for creating a signature externally.
   *
   * @return data to be signed externally.
   * @throws SignerCertificateRequiredException signer certificate must be provided using {@link SignatureBuilder#withSigningCertificate(X509Certificate)}
   * @throws ContainerWithoutFilesException     container must have at least one data file to be signed. Signature cannot be given on an empty container.
   */
  public abstract DataToSign buildDataToSign() throws SignerCertificateRequiredException, ContainerWithoutFilesException;

  /**
   * Open signature from an existing signature document (XAdES, PAdES, CAdES etc.)
   * <p>
   * The signature document must be complete, containing all the necessary data (e.g. Signer's certificate,
   * OCSP responses, Timestamps, signature values etc). An example would be a signature document in XAdES format which
   * is an XML document transformed into a byte array.
   *
   * @param signatureDocument complete signature document in bytes.
   * @return a signature object representing the signatureDocument.
   */
  public abstract Signature openAdESSignature(byte[] signatureDocument);

  /**
   * Set a city to the signature production place.
   *
   * @param cityName city to use on the signature production place.
   * @return builder for creating a signature
   */
  public SignatureBuilder withCity(String cityName) {
    signatureParameters.setCity(cityName);
    return this;
  }

  /**
   * Set a state or province to the signature production place.
   *
   * @param stateOrProvince name of the state or province on the signature production place.
   * @return builder for creating a signature
   */
  public SignatureBuilder withStateOrProvince(String stateOrProvince) {
    signatureParameters.setStateOrProvince(stateOrProvince);
    return this;
  }

  /**
   * Set a postal code to the signature production place.
   *
   * @param postalCode postal code on the signature production place.
   * @return builder for creating a signature.
   */
  public SignatureBuilder withPostalCode(String postalCode) {
    signatureParameters.setPostalCode(postalCode);
    return this;
  }

  /**
   * Set a country name to the signature production place.
   *
   * @param country name of the country on the signature production place.
   * @return builder for creating a signature.
   */
  public SignatureBuilder withCountry(String country) {
    signatureParameters.setCountry(country);
    return this;
  }

  /**
   * Set roles to the signer.
   *
   * @param roles list of roles of a signer.
   * @return builder for creating a signature.
   */
  public SignatureBuilder withRoles(String... roles) {
    if (signatureParameters.getRoles() == null) {
      signatureParameters.setRoles(asList(roles));
    } else {
      signatureParameters.getRoles().addAll(asList(roles));
    }
    return this;
  }

  /**
   * Set signature digest algorithm used to generate a signature.
   *
   * @param digestAlgorithm signature digest algorithm.
   * @return builder for creating a signature.
   */
  public SignatureBuilder withSignatureDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    signatureParameters.setDigestAlgorithm(digestAlgorithm);
    return this;
  }

  /**
   * Set a signature profile: Time Mark, Time Stamp, Archive Time Stamp or no profile. Default is Time Stamp.
   *
   * @param signatureProfile signature profile.
   * @return builder for creating a signature.
   */
  public SignatureBuilder withSignatureProfile(SignatureProfile signatureProfile) {
    if (policyDefinedByUser != null && isDefinedAllPolicyValues()
        && signatureProfile != SignatureProfile.LT_TM) {
      logger.debug("policyDefinedByUser:" + policyDefinedByUser.toString());
      logger.debug("signatureProfile:" + signatureProfile.toString());
      throw new NotSupportedException("Can't define signature policy if it's not LT_TM signature profile ");
    }
    signatureParameters.setSignatureProfile(signatureProfile);
    return this;
  }

  /**
   * Set a signing certificate to be used when creating data to be signed.
   *
   * @param certificate X509 signer's certificate.
   * @return builder for creating a signature.
   */
  public SignatureBuilder withSigningCertificate(X509Certificate certificate) {
    signatureParameters.setSigningCertificate(certificate);
    return this;
  }

  /**
   * Set signature ID.
   *
   * @param signatureId signature id.
   * @return builder for creating a signature.
   */
  public SignatureBuilder withSignatureId(String signatureId) {
    signatureParameters.setSignatureId(signatureId);
    return this;
  }

  /**
   * Set signature token to be used in the signing process.
   *
   * @param signatureToken signature token.
   * @return builder for creating a signature.
   */
  public SignatureBuilder withSignatureToken(SignatureToken signatureToken) {
    this.signatureToken = signatureToken;
    return this;
  }

  /**
   * Set encryption algorithm to be used in the signing process.
   *
   * @param encryptionAlgorithm encryption algorithm.
   * @return builder for creating a signature.
   */
  public SignatureBuilder withEncryptionAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
    signatureParameters.setEncryptionAlgorithm(encryptionAlgorithm);
    return this;
  }

  protected void setContainer(Container container) {
    this.container = container;
  }

  /**
   * Set signature policy parameters. Define signature profile first.
   *
   * @param signaturePolicy with defined parameters.
   * @return SignatureBuilder
   */
  public SignatureBuilder withOwnSignaturePolicy(Policy signaturePolicy) {
    if (signatureParameters.getSignatureProfile() != null
        && signatureParameters.getSignatureProfile() != SignatureProfile.LT_TM) {
      throw new NotSupportedException("Can't define signature policy if it's not LT_TM signature profile. Define it first. ");
    }
    policyDefinedByUser = signaturePolicy;
    return this;
  }
}
