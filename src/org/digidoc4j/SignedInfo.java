package org.digidoc4j;

import eu.europa.ec.markt.dss.DSSUtils;

import static eu.europa.ec.markt.dss.DigestAlgorithm.forXML;

public class SignedInfo {
  private byte[] digest;
  private DigestAlgorithm digestAlgorithm;

  @SuppressWarnings("UnusedDeclaration")
  private SignedInfo() {}

  public SignedInfo(byte[] signedInfo, DigestAlgorithm digestAlgorithm) {
    this.digestAlgorithm = digestAlgorithm;
    digest = DSSUtils.digest(forXML(digestAlgorithm.toString()), signedInfo);
  }

  public byte[] getDigest() {
    return digest;
  }

  public DigestAlgorithm getDigestAlgorithm() {
    return digestAlgorithm;
  }
}
