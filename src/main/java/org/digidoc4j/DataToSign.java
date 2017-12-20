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

import java.io.Serializable;

import org.digidoc4j.impl.SignatureFinalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 *   Data to be signed externally (e.g. in the Web by a browser plugin).
 * </p>
 * <p>
 *   {@link DataToSign#getDataToSign()} and {@link DataToSign#getDigestAlgorithm()} can be used to get the data bytes to be signed
 *   (this is usually data derived from signature parameters - SignedInfo) and
 *   digest algorithm (e.g. SHA-256, SHA-512 etc) used in signing.
 * </p>
 * <p>
 *   After a signature has been created externally, then it must be included back by calling
 *   {@link DataToSign#finalize(byte[])} with the signature value. This will return a {@link Signature} object
 *   with the signature value, OCSP response etc included.
 * </p>
 */
public class DataToSign implements Serializable {

  private static final Logger logger = LoggerFactory.getLogger(DataToSign.class);
  private byte[] dataToSign;

  private SignatureParameters signatureParameters;
  private SignatureFinalizer signatureFinalizer;

  /**
   * Constructor
   * @param data Digest value of the data
   * @param signatureParameters Signature parameters
   * @param signatureFinalizer Signature finalizer
   */
  public DataToSign(byte[] data, SignatureParameters signatureParameters, SignatureFinalizer signatureFinalizer) {
    this.dataToSign = data;
    this.signatureParameters = signatureParameters;
    this.signatureFinalizer = signatureFinalizer;
  }

  /**
   * Signature parameters used to create the signature.
   * @return signature parameters.
   */
  public SignatureParameters getSignatureParameters() {
    return signatureParameters;
  }

  /**
   * Signature digest algorithm to be used when creating the signature value.
   * @return signature digest algorithm.
   */
  public DigestAlgorithm getDigestAlgorithm() {
    return signatureParameters.getDigestAlgorithm();
  }

  /**
   * Data to be signed externally.
   * @return data bytes to be signed.
   */
  public byte[] getDataToSign() {
    return dataToSign;
  }

  /**
   * Finalize the signature by adding externally created signature value in bytes.
   * This will get OCSP verification etc. to finalize the signature.
   *
   * @param signatureValue externally created signature value bytes.
   * @return Finalized signature.
   */
  public Signature finalize(byte[] signatureValue) {
    logger.debug("Finalizing signature");
    return signatureFinalizer.finalizeSignature(signatureValue);
  }
}
