/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.test;

import eu.europa.esig.dss.model.DSSDocument;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.exceptions.ContainerWithoutFilesException;
import org.digidoc4j.exceptions.SignerCertificateRequiredException;
import org.digidoc4j.impl.SignatureFinalizer;

import java.util.ArrayList;

/**
 * Used in unit tests.
 */
public class MockSignatureBuilder extends SignatureBuilder {

  private static final byte[] DIGEST_TO_SIGN = new byte[]{105, 89, -46, 49, -63, -66, 66, -116, -35, 71, 112, -69, -2, 30, -88, 30, -43, -36, -121, -51, 60, -58, -16, -81, 26, -58, -120, -78, -7, -95, 13, -117};
  public static byte[] finalizedSignatureValue;

  @Override
  public DataToSign buildDataToSign() throws SignerCertificateRequiredException, ContainerWithoutFilesException {
    SignatureFinalizer signatureFinalizer = new SignatureFinalizer(new ArrayList<>(), null, null) {
      @Override
      public Signature finalizeSignature(byte[] signatureValue) {
        finalizedSignatureValue = signatureValue;
        return new MockSignature();
      }

      @Override
      public Signature createSignature(DSSDocument signedDocument) {
        return new MockSignature();
      }

      @Override
      public byte[] getDataToBeSigned() {
        return DIGEST_TO_SIGN;
      }

      @Override
      public Configuration getConfiguration() {
        return Configuration.getInstance();
      }

      @Override
      public SignatureParameters getSignatureParameters() {
        SignatureParameters signatureParameters = new SignatureParameters();
        signatureParameters.setSignatureDigestAlgorithm(DigestAlgorithm.SHA512);
        signatureParameters.setDataFileDigestAlgorithm(DigestAlgorithm.SHA512);
        return signatureParameters;
      }
    };
    return new DataToSign(DIGEST_TO_SIGN, signatureFinalizer);
  }

  @Override
  public Signature openAdESSignature(byte[] signatureDocument) {
    return null;
  }

  @Override
  protected Signature invokeSigningProcess() {
    return new MockSignature();
  }
}
