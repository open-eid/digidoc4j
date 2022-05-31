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

import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.X509Cert;

import java.util.Date;
import java.util.List;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */
public class MockSignature implements Signature {

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
  public String getUniqueId() {
    return null;
  }

  @Override
  public byte[] getOCSPNonce() {
    return new byte[0];
  }

  @Override
  public X509Cert getOCSPCertificate() {
    return null;
  }

  @Override
  public String getPostalCode() {
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
  public Date getTrustedSigningTime() {
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
  public String getStateOrProvince() {
    return null;
  }

  @Override
  public X509Cert getTimeStampTokenCertificate() {
    return null;
  }

  @Override
  public ValidationResult validateSignature() {
    return null;
  }

  @Override
  public byte[] getAdESSignature() {
    return new byte[0];
  }

}
