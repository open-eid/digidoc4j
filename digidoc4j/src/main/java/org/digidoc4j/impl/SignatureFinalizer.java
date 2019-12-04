/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl;

import eu.europa.esig.dss.model.DSSDocument;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureParameters;

import java.io.Serializable;
import java.util.List;

/**
 * Signature finalizer for datafiles signing process.
 * Used by {@link SignatureBuilder}, by {@link SignatureBuilder} generated {@link DataToSign} and for two step signing (with serialization or local storage).
 */
public abstract class SignatureFinalizer implements Serializable {

  protected List<DataFile> dataFiles;
  protected SignatureParameters signatureParameters;
  protected Configuration configuration;

  public SignatureFinalizer(List<DataFile> dataFiles, SignatureParameters signatureParameters, Configuration configuration) {
    this.dataFiles = dataFiles;
    this.signatureParameters = signatureParameters;
    this.configuration = configuration;
  }

  /**
   * Finalizes signing process and constructs signature object from signature value.
   *
   * @param signatureValue signature value bytes
   * @return signature object
   */
  public abstract Signature finalizeSignature(byte[] signatureValue);

  /**
   * Constructs signature object from signed document.
   *
   * @param signedDocument signed DSS document
   * @return signature object
   */
  public abstract Signature createSignature(DSSDocument signedDocument);

  /**
   * Get data to be signed in bytes.
   * @return data to be signed in bytes
   */
  public abstract byte[] getDataToBeSigned();

  /**
   * Returns configuration object related to given signature finalization process.
   * @return configuration object
   */
  public Configuration getConfiguration() {
    return configuration;
  }

  /**
   * Returns signature parameters object related to given signature finalization process.
   * @return signature parameters object
   */
  public SignatureParameters getSignatureParameters() {
    return signatureParameters;
  }
}
