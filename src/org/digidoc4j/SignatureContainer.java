package org.digidoc4j;

import java.util.List;

/**
 * Created by Kaarel Raspel on 23/03/17.
 */
public interface SignatureContainer extends BaseContainer {

  /**
   * Adds a new signature to the container.
   *
   * @param signature signature to be added.
   */
  void addSignature(Signature signature);

  /**
   * Returns a list of all signatures in the container.
   *
   * @return list of all signatures
   */
  List<Signature> getSignatures();

  /**
   * Removes the signature from the container
   * @param signature signature to be removed.
   */
  void removeSignature(Signature signature);

  /**
   * Extends signature profile to SignatureProfile
   *
   * @param profile signature profile
   * @see SignatureProfile
   */
  void extendSignatureProfile(SignatureProfile profile);
}
