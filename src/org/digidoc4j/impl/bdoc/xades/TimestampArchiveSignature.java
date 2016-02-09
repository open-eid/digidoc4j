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

import org.digidoc4j.SignatureProfile;

import eu.europa.esig.dss.xades.validation.XAdESSignature;

public class TimestampArchiveSignature extends TimestampSignature {

  public TimestampArchiveSignature(XAdESSignature dssSignature) {
    super(dssSignature);
  }

  @Override
  public SignatureProfile getProfile() {
    return SignatureProfile.LTA;
  }
}
