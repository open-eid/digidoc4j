/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.testutils;

import java.net.URI;
import java.util.Date;
import java.util.List;

import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.ContainerWithoutFilesException;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.exceptions.SignerCertificateRequiredException;
import org.digidoc4j.impl.SignatureFinalizer;

/**
 * Used in unit tests.
 */
public class TestSignatureBuilder extends SignatureBuilder {

  private static final byte[] DIGEST_TO_SIGN = new byte[]{105, 89, -46, 49, -63, -66, 66, -116, -35, 71, 112, -69, -2, 30, -88, 30, -43, -36, -121, -51, 60, -58, -16, -81, 26, -58, -120, -78, -7, -95, 13, -117};
  public static byte[] finalizedSignatureValue;

  @Override
  public DataToSign buildDataToSign() throws SignerCertificateRequiredException, ContainerWithoutFilesException {
    SignatureFinalizer signatureFinalizer = new SignatureFinalizer() {
      @Override
      public Signature finalizeSignature(byte[] signatureValue) {
        finalizedSignatureValue = signatureValue;
        return new TestSignature();
      }
    };
    return new DataToSign(DIGEST_TO_SIGN, signatureParameters, signatureFinalizer);
  }

  @Override
  protected Signature invokeSigningProcess() {
    return new TestSignature();
  }

  private static class TestSignature implements Signature {

    @Override
    public String getCity() {
      return null;
    }

    @Override
    public String getCountryName() {
      return null;
    }

    @Override
    public String getId() {
      return null;
    }

    @Override
    public byte[] getOcspNonce() {
      return new byte[0];
    }

    @Override
    public X509Cert getOCSPCertificate() {
      return null;
    }

    @Override
    public String getPolicy() {
      return null;
    }

    @Override
    public String getPostalCode() {
      return null;
    }

    @Override
    public Date getProducedAt() {
      return null;
    }

    @Override
    public Date getOCSPResponseCreationTime() {
      return null;
    }

    @Override
    public Date getTimeStampCreationTime() {
      return null;
    }

    @Override
    public SignatureProfile getProfile() {
      return null;
    }

    @Override
    public String getSignatureMethod() {
      return null;
    }

    @Override
    public List<String> getSignerRoles() {
      return null;
    }

    @Override
    public X509Cert getSigningCertificate() {
      return null;
    }

    @Override
    public Date getClaimedSigningTime() {
      return null;
    }

    @Override
    public Date getSigningTime() {
      return null;
    }

    @Override
    public URI getSignaturePolicyURI() {
      return null;
    }

    @Override
    public String getStateOrProvince() {
      return null;
    }

    @Override
    public X509Cert getTimeStampTokenCertificate() {
      return null;
    }

    @Override
    public List<DigiDoc4JException> validate() {
      return null;
    }

    @Override
    public byte[] getRawSignature() {
      return new byte[0];
    }
  }
}
