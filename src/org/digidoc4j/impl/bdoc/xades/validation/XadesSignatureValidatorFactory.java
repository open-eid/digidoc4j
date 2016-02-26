/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.xades.validation;

import java.util.List;

import org.digidoc4j.Configuration;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.bdoc.xades.XadesSignature;
import org.digidoc4j.impl.bdoc.xades.XadesSignatureValidator;
import org.digidoc4j.impl.bdoc.xades.XadesValidationReportGenerator;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class XadesSignatureValidatorFactory {

  private Configuration configuration;
  private SignedDocumentValidator validator;
  private List<DSSDocument> detachedContents;
  private DSSDocument xadesDocument;
  private XadesSignature signature;

  public XadesSignatureValidator create() {
    XadesValidationReportGenerator xadesReportGenerator = new XadesValidationReportGenerator(xadesDocument, detachedContents, configuration);
    xadesReportGenerator.setValidator(validator);
    SignatureProfile profile = signature.getProfile();
    XadesSignatureValidator xadesValidator;
    if (profile == SignatureProfile.B_BES) {
      xadesValidator = new XadesSignatureValidator(xadesReportGenerator, signature);
    } else if (profile == SignatureProfile.LT_TM) {
      xadesValidator = new TimemarkSignatureValidator(xadesReportGenerator, signature);
    } else if (profile == SignatureProfile.LT) {
      xadesValidator = new TimestampSignatureValidator(xadesReportGenerator, signature, configuration);
    } else {
      xadesValidator = new TimestampSignatureValidator(xadesReportGenerator, signature, configuration);
    }
    return xadesValidator;
  }

  public void setConfiguration(Configuration configuration) {
    this.configuration = configuration;
  }

  public void setDetachedContents(List<DSSDocument> detachedContents) {
    this.detachedContents = detachedContents;
  }

  public void setSignature(XadesSignature signature) {
    this.signature = signature;
  }

  public void setValidator(SignedDocumentValidator validator) {
    this.validator = validator;
  }

  public void setXadesDocument(DSSDocument xadesDocument) {
    this.xadesDocument = xadesDocument;
  }
}
