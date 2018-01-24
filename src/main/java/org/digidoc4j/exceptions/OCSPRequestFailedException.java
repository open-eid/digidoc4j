/* DigiDoc4J library
*
* This software is released under either the GNU Library General Public
* License (see LICENSE.LGPL).
*
* Note that the only valid version of the LGPL license as far as this
* project is concerned is the original GNU Library General Public License
* Version 2.1, February 1999
*/

package org.digidoc4j.exceptions;

public class OCSPRequestFailedException extends DigiDoc4JException {

  public static final String MESSAGE = "OCSP request failed. Please check GitHub Wiki for more information: https://github.com/open-eid/digidoc4j/wiki/Questions-&-Answers#if-ocsp-request-has-failed";

  public OCSPRequestFailedException(Throwable e) {
    super(MESSAGE, e);
  }
  
  public OCSPRequestFailedException(String sigId) {
    super(MESSAGE, sigId);
  }
}
