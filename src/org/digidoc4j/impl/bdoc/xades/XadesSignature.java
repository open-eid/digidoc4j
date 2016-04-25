/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.impl.bdoc.xades;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import org.digidoc4j.SignatureProfile;
import org.digidoc4j.X509Cert;
import org.digidoc4j.impl.bdoc.xades.validation.XadesValidationResult;

import eu.europa.esig.dss.xades.validation.XAdESSignature;

public interface XadesSignature extends Serializable {

  String getId();

  String getCity();

  String getStateOrProvince();

  String getPostalCode();

  String getCountryName();

  List<String> getSignerRoles();

  X509Cert getSigningCertificate();

  SignatureProfile getProfile();

  String getSignatureMethod();

  Date getSigningTime();

  Date getTrustedSigningTime();

  Date getOCSPResponseCreationTime();

  X509Cert getOCSPCertificate();

  Date getTimeStampCreationTime();

  X509Cert getTimeStampTokenCertificate();

  byte[] getAdESSignature();

  XAdESSignature getDssSignature();

  XadesValidationResult validate();

}
