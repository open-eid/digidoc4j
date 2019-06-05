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

import org.apache.commons.lang3.SerializationUtils;
import org.digidoc4j.AbstractTest;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerOpener;
import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureFinalizerBuilder;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.SignatureValidationResult;
import org.digidoc4j.test.retry.Retry;
import org.digidoc4j.test.retry.RetryRule;
import org.junit.Rule;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

import static org.digidoc4j.Container.DocumentType.ASICE;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ContainerSigningWithOutSerializationTest extends AbstractTest {

  // TODO: Given tests are at the moment flaky for unknown reason. Running second time in case of a fault.
  @Rule
  public RetryRule retryRule = new RetryRule(2);

  @Test
  @Retry
  public void emptyBdocTwoStepSigningWithoutSerialization() {
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);
    Container container = ContainerBuilder.aContainer(BDOC)
          .withConfiguration(configuration)
          .build();
    assertBDocContainer(container);
    container.addDataFile(new ByteArrayInputStream("something".getBytes(StandardCharsets.UTF_8)), "file name", "text/plain");

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT_TM)
          .buildDataToSign();

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    // Raw container stored locally
    container.save(out);

    // Still need to store/serialize signature parameters and signature digest, but these values are very small
    byte[] signatureParametersSerialized = SerializationUtils.serialize(dataToSign.getSignatureParameters());
    SignatureParameters signatureParameters = SerializationUtils.deserialize(signatureParametersSerialized);
    byte[] signatureDigest = pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());

    // If given container was empty before then have to use ContainerBuilder using the exact type as input
    // because using ContainerOpener for empty container always result with AsicE container.
    // Using ContainerOpener for not-empty container is fine.
    container = ContainerBuilder.aContainer(BDOC)
          .withConfiguration(configuration)
          .fromStream(new ByteArrayInputStream(out.toByteArray()))
          .build();
    assertBDocContainer(container);

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, signatureParameters);
    Signature signature = signatureFinalizer.finalizeSignature(signatureDigest);

    container.addSignature(signature);
    assertTimemarkSignature(signature);
    assertValidSignature(signature);

    SignatureValidationResult validationResult = container.validate();
    assertTrue(validationResult.isValid());
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  @Retry
  public void emptyAsicETwoStepSigningWithoutSerialization() {
    Configuration configuration = Configuration.getInstance();
    Container container = ContainerBuilder.aContainer(ASICE).withConfiguration(configuration).build();
    assertAsicEContainer(container);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(this.pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT)
          .buildDataToSign();

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    container.save(out);

    byte[] signatureParametersSerialized = SerializationUtils.serialize(dataToSign.getSignatureParameters());
    SignatureParameters signatureParameters = SerializationUtils.deserialize(signatureParametersSerialized);
    byte[] signatureDigest = this.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());

    container = ContainerBuilder.aContainer(ASICE)
          .withConfiguration(Configuration.getInstance())
          .fromStream(new ByteArrayInputStream(out.toByteArray()))
          .build();
    assertAsicEContainer(container);

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, signatureParameters);
    Signature signature = signatureFinalizer.finalizeSignature(signatureDigest);

    container.addSignature(signature);
    assertTimestampSignature(signature);
    assertValidSignature(signature);

    SignatureValidationResult validationResult = container.validate();
    assertTrue(validationResult.isValid());
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  @Retry
  public void signedBDocTwoStepSigningWithoutSerialization() {
    Container container = this.openContainerBy(Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc"));
    assertBDocContainer(container);
    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(this.pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT_TM)
          .buildDataToSign();

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    container.save(out);

    byte[] signatureParametersSerialized = SerializationUtils.serialize(dataToSign.getSignatureParameters());
    SignatureParameters signatureParameters = SerializationUtils.deserialize(signatureParametersSerialized);
    byte[] signatureDigest = this.sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());

    container = ContainerOpener.open(new ByteArrayInputStream(out.toByteArray()), Configuration.getInstance());
    assertBDocContainer(container);

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, signatureParameters);
    Signature signature = signatureFinalizer.finalizeSignature(signatureDigest);

    container.addSignature(signature);
    assertTimemarkSignature(signature);
    assertValidSignature(signature);

    SignatureValidationResult validationResult = container.validate();
    assertTrue(validationResult.isValid());
    assertEquals(2, container.getSignatures().size());
  }
}