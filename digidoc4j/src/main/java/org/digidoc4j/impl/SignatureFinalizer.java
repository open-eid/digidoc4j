package org.digidoc4j.impl;

import eu.europa.esig.dss.DSSDocument;
import org.digidoc4j.Configuration;
import org.digidoc4j.DataFile;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureParameters;

import java.io.Serializable;
import java.util.List;

public abstract class SignatureFinalizer implements Serializable {

  protected List<DataFile> dataFiles;
  protected SignatureParameters signatureParameters;
  protected Configuration configuration;

  public SignatureFinalizer(List<DataFile> dataFiles, SignatureParameters signatureParameters, Configuration configuration) {
    this.dataFiles = dataFiles;
    this.signatureParameters = signatureParameters;
    this.configuration = configuration;
  }

  public abstract Signature finalizeSignature(byte[] signatureValue);

  public abstract Signature createSignature(DSSDocument signedDocument);

  public abstract byte[] getDataToBeSigned();

  public Configuration getConfiguration() {
    return configuration;
  }

  public List<DataFile> getDataFiles() {
    return dataFiles;
  }

  public SignatureParameters getSignatureParameters() {
    return signatureParameters;
  }
}
