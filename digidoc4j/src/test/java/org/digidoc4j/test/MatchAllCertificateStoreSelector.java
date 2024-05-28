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

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Selector;

public class MatchAllCertificateStoreSelector implements Selector<X509CertificateHolder> {

  @Override
  public boolean match(X509CertificateHolder obj) {
    return true;
  }

  @Override
  public Object clone() {
    return new MatchAllCertificateStoreSelector();
  }

}
