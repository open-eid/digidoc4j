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
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.digidoc4j.Container.DocumentType.ASICE;
import static org.digidoc4j.Container.DocumentType.BDOC;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ContainerSigningWithOutDataToSignSerializationTest extends AbstractTest {

  @Test
  public void emptyBdocTwoStepSigning() {
    Container container = createEmptyContainerBy(Container.DocumentType.BDOC);
    container.addDataFile(new ByteArrayInputStream("something".getBytes(StandardCharsets.UTF_8)), "file name", "text/plain");

    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT)
          .buildDataToSign();

    ByteArrayOutputStream output = new ByteArrayOutputStream();
    // Storing container to memory (can also be stored locally to disk)
    container.save(output);

    // Still need to store/serialize signature parameters, fortunately these values are very small.
    // Simulating serialisation to prove it's serializability
    byte[] signatureParametersSerialized = SerializationUtils.serialize(dataToSign.getSignatureParameters());
    SignatureParameters signatureParameters = SerializationUtils.deserialize(signatureParametersSerialized);

    // Signature value for example from external system
    byte[] signatureValue = pkcs12SignatureToken.sign(dataToSign.getDigestAlgorithm(), dataToSign.getDataToSign());

    // Loading stored container.
    // If given container was empty before then have to use ContainerBuilder using the exact type as input
    // because using ContainerOpener for empty container always result with AsicE container.
    // Using ContainerOpener is fine for opening empty AsicE container or other type not empty container.
    container = ContainerBuilder.aContainer(BDOC)
          .withConfiguration(configuration)
          .fromStream(new ByteArrayInputStream(output.toByteArray()))
          .build();
    assertBDocContainer(container);

    // Building signature finalizer from loaded container and stored/deserialized signature parameters
    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, signatureParameters);
    Signature signature = signatureFinalizer.finalizeSignature(signatureValue);

    container.addSignature(signature);
    assertLtSignature(signature);
    assertValidSignature(signature);

    SignatureValidationResult validationResult = container.validate();
    assertTrue(validationResult.isValid());
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void emptyAsicETwoStepSigning() {
    Container container = createEmptyContainerBy(ASICE);
    container.addDataFile("src/test/resources/testFiles/helper-files/test.txt", "text/plain");
    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT)
          .buildDataToSign();

    ByteArrayOutputStream output = new ByteArrayOutputStream();
    container.save(output);

    byte[] signatureParametersSerialized = SerializationUtils.serialize(dataToSign.getSignatureParameters());
    SignatureParameters signatureParameters = SerializationUtils.deserialize(signatureParametersSerialized);

    byte[] signatureValue = sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());

    container = ContainerBuilder.aContainer(ASICE)
          .withConfiguration(Configuration.getInstance())
          .fromStream(new ByteArrayInputStream(output.toByteArray()))
          .build();
    assertAsicEContainer(container);

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, signatureParameters);
    Signature signature = signatureFinalizer.finalizeSignature(signatureValue);

    container.addSignature(signature);
    assertLtSignature(signature);
    assertValidSignature(signature);

    SignatureValidationResult validationResult = container.validate();
    assertTrue(validationResult.isValid());
    assertEquals(1, container.getSignatures().size());
  }

  @Test
  public void signedBDocTwoStepSigning() {
    Container container = openContainerBy(Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc"));
    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT)
          .buildDataToSign();

    ByteArrayOutputStream output = new ByteArrayOutputStream();
    container.save(output);

    byte[] signatureParametersSerialized = SerializationUtils.serialize(dataToSign.getSignatureParameters());
    SignatureParameters signatureParameters = SerializationUtils.deserialize(signatureParametersSerialized);

    byte[] signatureValue = sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());

    container = ContainerOpener.open(new ByteArrayInputStream(output.toByteArray()), Configuration.getInstance());
    assertBDocContainer(container);

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, signatureParameters);
    Signature signature = signatureFinalizer.finalizeSignature(signatureValue);

    container.addSignature(signature);
    assertLtSignature(signature);
    assertValidSignature(signature);

    SignatureValidationResult validationResult = container.validate();
    assertTrue(validationResult.isValid());
    assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void signedAsicETwoStepSigning() {
    Container container = openContainerBy(Paths.get("src/test/resources/testFiles/valid-containers/valid-asice.asice"));
    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT)
          .buildDataToSign();

    ByteArrayOutputStream output = new ByteArrayOutputStream();
    container.save(output);

    byte[] signatureParametersSerialized = SerializationUtils.serialize(dataToSign.getSignatureParameters());
    SignatureParameters signatureParameters = SerializationUtils.deserialize(signatureParametersSerialized);

    byte[] signatureValue = sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());

    container = ContainerOpener.open(new ByteArrayInputStream(output.toByteArray()), Configuration.getInstance());
    assertAsicEContainer(container);

    SignatureFinalizer signatureFinalizer = SignatureFinalizerBuilder.aFinalizer(container, signatureParameters);
    Signature signature = signatureFinalizer.finalizeSignature(signatureValue);

    container.addSignature(signature);
    assertLtSignature(signature);
    assertValidSignature(signature);

    SignatureValidationResult validationResult = container.validate();
    assertTrue(validationResult.isValid());
    assertEquals(2, container.getSignatures().size());
  }

  @Test
  public void twoStepSigningSigningTimeAssertion() throws InterruptedException {
    Container container = openContainerBy(Paths.get("src/test/resources/testFiles/valid-containers/valid-bdoc-tm.bdoc"));

    // Signature object returned signing dates have milliseconds removed, truncated also from test data
    Instant claimedSigningTimeLowerBound = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    DataToSign dataToSign = SignatureBuilder.aSignature(container)
          .withSigningCertificate(pkcs12SignatureToken.getCertificate())
          .withSignatureProfile(SignatureProfile.LT)
          .buildDataToSign();
    Instant claimedSigningTimeUpperBound = Instant.now();

    byte[] signatureValue = sign(dataToSign.getDataToSign(), dataToSign.getDigestAlgorithm());

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    container.save(out);
    container = ContainerOpener.open(new ByteArrayInputStream(out.toByteArray()), Configuration.getInstance());

    // Artificial delay to make claimed signing time and actual signing time differ
    Thread.sleep(1000);

    Instant trustedSigningTimeLowerBound = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    Signature signature = SignatureFinalizerBuilder.aFinalizer(container, dataToSign.getSignatureParameters())
           .finalizeSignature(signatureValue);
    Instant trustedSigningTimeUpperBound = Instant.now();

    Date trustedSigningTime = signature.getTrustedSigningTime();
    assertTimeInBounds(trustedSigningTime, trustedSigningTimeLowerBound, trustedSigningTimeUpperBound, Duration.ofSeconds(10));

    Date claimedSigningTime = signature.getClaimedSigningTime();
    assertTimeInBounds(claimedSigningTime, claimedSigningTimeLowerBound, claimedSigningTimeUpperBound, Duration.ZERO);
  }

}