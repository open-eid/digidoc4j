package org.digidoc4j.impl.bdoc;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.junit.Assert;
import org.junit.Test;

/**
 * Created by Andrei on 26.04.2017.
 */

public class SignatureTimeTest extends AbstractTest {

  @Test
  public void signatureProfileLTTMTest() throws Exception {
    Container container = this.createNonEmptyContainer();
    BDocSignature signature = (BDocSignature) this.createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.LT_TM, this.pkcs12SignatureToken);
    container.addSignature(signature);
    Assert.assertEquals(signature.getSigningTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void signatureProfileLTTest() throws Exception {
    Container container = this.createNonEmptyContainer();
    AsicESignature signature = (AsicESignature) this.createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.LT, this.pkcs12SignatureToken);
    container.addSignature(signature);
    Assert.assertEquals(signature.getSigningTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void signatureProfileLTATest() throws Exception {
    Container container = this.createNonEmptyContainer();
    AsicESignature signature = (AsicESignature) this.createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.LTA, this.pkcs12SignatureToken);
    container.addSignature(signature);
    Assert.assertEquals(signature.getSigningTime(), signature.getTrustedSigningTime());
  }

  @Test
  public void signatureProfileB_BESTest() throws Exception {
    Container container = this.createNonEmptyContainer();
    AsicESignature signature = (AsicESignature) this.createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.B_BES, this.pkcs12SignatureToken);
    container.addSignature(signature);
    Assert.assertEquals(signature.getSigningTime(), signature.getClaimedSigningTime());
  }

  @Test
  public void signatureProfileB_EPESTest() throws Exception {
    Container container = this.createNonEmptyContainer();
    AsicESignature signature = (AsicESignature) this.createSignatureBy(Container.DocumentType.BDOC, SignatureProfile.B_EPES, this.pkcs12SignatureToken);
    container.addSignature(signature);
    Assert.assertEquals(signature.getSigningTime(), signature.getClaimedSigningTime());
  }

  /*
   * RESTRICTED METHODS
   */

  @Override
  protected void before() {
    this.configuration = Configuration.of(Configuration.Mode.TEST);
  }

}
