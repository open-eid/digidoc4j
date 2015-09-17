/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc;

import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignedInfo;
import org.digidoc4j.exceptions.ContainerWithoutFilesException;
import org.digidoc4j.exceptions.SignatureTokenMissingException;
import org.digidoc4j.exceptions.SignerCertificateRequiredException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BDocSignatureBuilder extends SignatureBuilder {

  private final static Logger logger = LoggerFactory.getLogger(BDocSignatureBuilder.class);

  @Override
  public DataToSign buildDataToSign() throws SignerCertificateRequiredException, ContainerWithoutFilesException {
    logger.debug("Building data to sign");
    AsicFacade asicFacade = getAsicFacade();
    asicFacade.setSignatureParameters(signatureParameters);
    SignedInfo signedInfo = asicFacade.prepareSigning(signatureParameters.getSigningCertificate());
    DataToSign signature = new DataToSign(signedInfo.getDigestToSign(), signedInfo.getSignatureParameters(), asicFacade);
    return signature;
  }

  @Override
  public Signature invokeSigningProcess() throws SignatureTokenMissingException {
    logger.debug("Invoking signing");
    AsicFacade asicFacade = getAsicFacade();
    asicFacade.setSignatureParameters(signatureParameters);
    return asicFacade.sign(signatureToken);
  }

  private AsicFacade getAsicFacade() {
    BDocContainer container = (BDocContainer) signatureParameters.getContainer();
    return container.getAsicFacade();
  }
}
