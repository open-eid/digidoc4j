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

import java.util.ArrayList;

import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureToken;
import org.digidoc4j.impl.ddoc.DDocFacade;
import org.mockito.Mockito;

import ee.sk.digidoc.DigiDocException;
import ee.sk.digidoc.SignedDoc;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public class MockDDocFacade extends DDocFacade {

  ee.sk.digidoc.Signature signature = Mockito.spy(new ee.sk.digidoc.Signature(new SignedDoc()));

  @Override
  public void extendTo(SignatureProfile profile) {
    super.ddoc = Mockito.spy(new SignedDoc());
    this.getConfirmationThrowsException();
    this.doReturnSignatureList();
    super.extendTo(profile);
  }

  @Override
  public Signature sign(SignatureToken signatureToken) {
    super.ddoc = Mockito.spy(new SignedDoc());
    this.ddocSignature = Mockito.mock(ee.sk.digidoc.Signature.class);
    this.doReturnSignatureList();
    try {
      Mockito.doReturn("A".getBytes()).when(this.ddocSignature).calculateSignedInfoXML();
    } catch (DigiDocException ignored) {
    }
    this.getConfirmationThrowsException();
    return super.sign(signatureToken);
  }

  @Override
  protected ee.sk.digidoc.Signature calculateSignature(SignatureToken signatureToken) {
    return this.signature;
  }

  private void getConfirmationThrowsException() {
    try {
      Mockito.doThrow(new DigiDocException(1, "test", new Throwable())).when(this.signature).getConfirmation();
    } catch (DigiDocException e) {
      e.printStackTrace();
    }
  }

  private void doReturnSignatureList() {
    ArrayList<ee.sk.digidoc.Signature> signatures = new ArrayList<>();
    signatures.add(this.signature);
    Mockito.doReturn(signatures).when(this.ddoc).getSignatures();
  }

}

