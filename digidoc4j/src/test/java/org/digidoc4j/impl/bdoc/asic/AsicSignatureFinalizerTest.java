package org.digidoc4j.impl.bdoc.asic;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureFinalizerBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.impl.SignatureFinalizer;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class AsicSignatureFinalizerTest extends AbstractTest {

  @Test
  public void bdocSignatureFinalization() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile(new ByteArrayInputStream("something".getBytes(StandardCharsets.UTF_8)), "file name", "text/plain");

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT_TM)
          .buildDataToSign();

    byte[] signatureDigest = sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, dataToSign.getSignatureParameters());
    Signature signature = signatureFinalizer.finalizeSignature(signatureDigest);
    assertTimemarkSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void asicESignatureFinalization() {
    Container container = createEmptyContainerBy(Container.DocumentType.ASICE);
    container.addDataFile(new ByteArrayInputStream("something".getBytes(StandardCharsets.UTF_8)), "file name", "text/plain");

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT)
          .buildDataToSign();

    byte[] signatureDigest = sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, dataToSign.getSignatureParameters());
    Signature signature = signatureFinalizer.finalizeSignature(signatureDigest);
    assertTimestampSignature(signature);
    assertValidSignature(signature);
  }

  @Test
  public void signatureFinalizerFieldsEqualToDataToSign() {
    Container container = createEmptyContainerBy(Container.DocumentType.ASICE);
    container.addDataFile(new ByteArrayInputStream("something".getBytes(StandardCharsets.UTF_8)), "file name", "text/plain");

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT)
          .buildDataToSign();

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, dataToSign.getSignatureParameters());
    assertEquals(dataToSign.getSignatureParameters(), signatureFinalizer.getSignatureParameters());
    assertEquals(dataToSign.getConfiguration(), signatureFinalizer.getConfiguration());
    assertEquals(dataToSign.getDigestAlgorithm(), signatureFinalizer.getSignatureParameters().getDigestAlgorithm());
  }

  @Test
  public void getDataToSignBytesEqualToValueFromDataToSignObject() {
    Container container = createEmptyContainerBy(Container.DocumentType.ASICE);
    container.addDataFile(new ByteArrayInputStream("something".getBytes(StandardCharsets.UTF_8)), "file name", "text/plain");

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT)
          .buildDataToSign();

    byte[] dataToSignBytes = dataToSign.getDataToSign();
    byte[] signatureDigest = sign(dataToSignBytes, dataToSign.getDigestAlgorithm());

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, dataToSign.getSignatureParameters());

    assertThat(dataToSignBytes, equalTo(signatureFinalizer.getDataToBeSigned()));

    Signature signature = signatureFinalizer.finalizeSignature(signatureDigest);
    assertTimestampSignature(signature);
    assertValidSignature(signature);

    assertThat(dataToSignBytes, equalTo(signatureFinalizer.getDataToBeSigned()));
  }
}
