/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.xades;

import org.digidoc4j.SignatureProfile;
import org.digidoc4j.X509Cert;

import java.util.Date;

public class LongTermSignature extends TimemarkSignature {

  private transient TimestampSignatureComponent timestampComponent;

  public LongTermSignature(XadesValidationReportGenerator xadesReportGenerator) {
    super(xadesReportGenerator);
  }

  @Override
  public SignatureProfile getProfile() {
    return SignatureProfile.LT;
  }

  @Override
  public X509Cert getTimeStampTokenCertificate() {
    return getTimestampSignatureComponent().getTimeStampTokenCertificate();
  }

  @Override
  public Date getTimeStampCreationTime() {
    return getTimestampSignatureComponent().getTimeStampCreationTime();
  }

  @Override
  public Date getTrustedSigningTime() {
    return getTimeStampCreationTime();
  }

  private TimestampSignatureComponent getTimestampSignatureComponent() {
    if (timestampComponent == null) {
      timestampComponent = new TimestampSignatureComponent(getDssSignature());
    }
    return timestampComponent;
  }
}
