/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.ddoc;

import java.security.cert.X509Certificate;

import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.exceptions.ContainerWithoutFilesException;
import org.digidoc4j.exceptions.SignerCertificateRequiredException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DDocSignatureBuilder extends SignatureBuilder {

  private final static Logger logger = LoggerFactory.getLogger(DDocSignatureBuilder.class);

  @Override
  public DataToSign buildDataToSign() throws SignerCertificateRequiredException, ContainerWithoutFilesException {
    logger.debug("Building data to sign");
    DDocFacade ddocFacade = getJDigiDocFacade();
    ddocFacade.setSignatureParameters(signatureParameters);
    X509Certificate signingCertificate = signatureParameters.getSigningCertificate();
    SignedInfo signedInfo = ddocFacade.prepareSigning(signingCertificate);
    return new DataToSign(signedInfo.getDigestToSign(), signatureParameters, ddocFacade);
  }

  @Override
  protected Signature invokeSigningProcess() {
    DDocFacade ddocFacade = getJDigiDocFacade();
    ddocFacade.setSignatureParameters(signatureParameters);
    return ddocFacade.sign(signatureToken);
  }

  @Override
  public Signature openAdESSignature(byte[] signatureDocument) {
    DDocFacade ddocFacade = getJDigiDocFacade();
    ddocFacade.setSignatureParameters(signatureParameters);
    ddocFacade.addRawSignature(signatureDocument);
    int signatureIndex = ddocFacade.getSignatures().size() - 1;
    Signature signature = ddocFacade.getSignatures().get(signatureIndex);
    return signature;
  }

  private DDocFacade getJDigiDocFacade() {
    return ((DDocContainer)container).getJDigiDocFacade();
  }
}
