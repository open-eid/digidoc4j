/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.cades;

import eu.europa.esig.dss.model.FileDocument;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.X509Cert;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public abstract class AsicContainerTimestampTest<T extends AsicContainerTimestamp> {

  protected abstract T createDefaultAsicContainerTimestampWith(CadesTimestamp cadesTimestamp);
  protected abstract T createDefaultAsicContainerTimestampWith(CadesTimestamp cadesTimestamp, AsicArchiveManifest archiveManifest);

  @Test
  public void createInstance_WhenCadesTimestampIsNull_ThrowsNullPointerException() {
    assertThrows(
            NullPointerException.class,
            () -> createDefaultAsicContainerTimestampWith(null)
    );
  }

  @Test
  public void getCadesTimestamp_WhenCadesTimestampHasBeenProvidedOnCreation_ReturnsSameInstance() {
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp);

    CadesTimestamp result = asicContainerTimestamp.getCadesTimestamp();

    assertThat(result, sameInstance(cadesTimestamp));
    verifyNoInteractions(cadesTimestamp);
  }

  @Test
  public void getArchiveManifest_WhenManifestHasNotBeenProvidedOnCreation_ReturnsNull() {
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp);

    AsicArchiveManifest result = asicContainerTimestamp.getArchiveManifest();

    assertThat(result, nullValue());
    verifyNoInteractions(cadesTimestamp);
  }

  @Test
  public void getArchiveManifest_WhenManifestHasBeenSetToNullOnCreation_ReturnsNull() {
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp, null);

    AsicArchiveManifest result = asicContainerTimestamp.getArchiveManifest();

    assertThat(result, nullValue());
    verifyNoInteractions(cadesTimestamp);
  }

  @Test
  public void getArchiveManifest_WhenManifestHasBeenProvidedOnCreation_ReturnsSameInstance() {
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    AsicArchiveManifest asicArchiveManifest = mock(AsicArchiveManifest.class);
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp, asicArchiveManifest);

    AsicArchiveManifest result = asicContainerTimestamp.getArchiveManifest();

    assertThat(result, sameInstance(asicArchiveManifest));
    verifyNoInteractions(cadesTimestamp, asicArchiveManifest);
  }

  @Test
  public void getCertificate_WhenCadesTimestampWrappedIntoAsicContainerTimestamp_RequestIsDelegatedToWrappedCadesTimestamp() {
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    X509Cert x509Cert = mock(X509Cert.class);
    doReturn(x509Cert).when(cadesTimestamp).getCertificate();
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp);

    X509Cert result = asicContainerTimestamp.getCertificate();

    assertThat(result, sameInstance(x509Cert));
    verify(cadesTimestamp).getCertificate();
    verifyNoMoreInteractions(cadesTimestamp);
    verifyNoInteractions(x509Cert);
  }

  @Test
  public void getCreationTime_WhenCadesTimestampWrappedIntoAsicContainerTimestamp_RequestIsDelegatedToWrappedCadesTimestamp() {
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    Date creationTime = mock(Date.class);
    doReturn(creationTime).when(cadesTimestamp).getCreationTime();
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp);

    Date result = asicContainerTimestamp.getCreationTime();

    assertThat(result, sameInstance(creationTime));
    verify(cadesTimestamp).getCreationTime();
    verifyNoMoreInteractions(cadesTimestamp);
    verifyNoInteractions(creationTime);
  }

  @Test
  public void getTimeStampToken_WhenCadesTimestampWrappedIntoAsicContainerTimestamp_RequestIsDelegatedToWrappedCadesTimestamp() {
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    TimeStampToken timeStampToken = mock(TimeStampToken.class);
    doReturn(timeStampToken).when(cadesTimestamp).getTimeStampToken();
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp);

    TimeStampToken result = asicContainerTimestamp.getTimeStampToken();

    assertThat(result, sameInstance(timeStampToken));
    verify(cadesTimestamp).getTimeStampToken();
    verifyNoMoreInteractions(cadesTimestamp);
    verifyNoInteractions(timeStampToken);
  }

  @Test
  public void getDigestAlgorithm_WhenDigestAlgorithmIsSha1_ReturnsDigestAlgorithm() {
    getDigestAlgorithm_WhenDigestAlgorithmIsSupported_ReturnsDigestAlgorithm(DigestAlgorithm.SHA1);
  }

  @Test
  public void getDigestAlgorithm_WhenDigestAlgorithmIsSha224_ReturnsDigestAlgorithm() {
    getDigestAlgorithm_WhenDigestAlgorithmIsSupported_ReturnsDigestAlgorithm(DigestAlgorithm.SHA224);
  }

  @Test
  public void getDigestAlgorithm_WhenDigestAlgorithmIsSha256_ReturnsDigestAlgorithm() {
    getDigestAlgorithm_WhenDigestAlgorithmIsSupported_ReturnsDigestAlgorithm(DigestAlgorithm.SHA256);
  }

  @Test
  public void getDigestAlgorithm_WhenDigestAlgorithmIsSha384_ReturnsDigestAlgorithm() {
    getDigestAlgorithm_WhenDigestAlgorithmIsSupported_ReturnsDigestAlgorithm(DigestAlgorithm.SHA384);
  }

  @Test
  public void getDigestAlgorithm_WhenDigestAlgorithmIsSha512_ReturnsDigestAlgorithm() {
    getDigestAlgorithm_WhenDigestAlgorithmIsSupported_ReturnsDigestAlgorithm(DigestAlgorithm.SHA512);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void getDigestAlgorithm_WhenDigestAlgorithmIsSupported_ReturnsDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    TimeStampToken timeStampToken = mock(TimeStampToken.class);
    doReturn(timeStampToken).when(cadesTimestamp).getTimeStampToken();
    TimeStampTokenInfo timeStampTokenInfo = mock(TimeStampTokenInfo.class);
    doReturn(timeStampTokenInfo).when(timeStampToken).getTimeStampInfo();
    ASN1ObjectIdentifier objectIdentifier = new ASN1ObjectIdentifier(digestAlgorithm.getDssDigestAlgorithm().getOid());
    doReturn(objectIdentifier).when(timeStampTokenInfo).getMessageImprintAlgOID();
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp);

    DigestAlgorithm result = asicContainerTimestamp.getDigestAlgorithm();

    assertThat(result, sameInstance(digestAlgorithm));
    verify(cadesTimestamp).getTimeStampToken();
    verify(timeStampToken).getTimeStampInfo();
    verify(timeStampTokenInfo).getMessageImprintAlgOID();
    verifyNoMoreInteractions(cadesTimestamp, timeStampToken, timeStampTokenInfo);
  }

  @Test
  public void getDigestAlgorithm_WhenDigestAlgorithmIsMd2_ThrowsIllegalStateException() {
    getDigestAlgorithm_WhenDigestAlgorithmIsNotSupported_ThrowsIllegalStateException(
            eu.europa.esig.dss.enumerations.DigestAlgorithm.MD2);
  }

  @Test
  public void getDigestAlgorithm_WhenDigestAlgorithmIsMd5_ThrowsIllegalStateException() {
    getDigestAlgorithm_WhenDigestAlgorithmIsNotSupported_ThrowsIllegalStateException(
            eu.europa.esig.dss.enumerations.DigestAlgorithm.MD5);
  }

  @Test
  public void getDigestAlgorithm_WhenDigestAlgorithmIsRipeMd160_ThrowsIllegalStateException() {
    getDigestAlgorithm_WhenDigestAlgorithmIsNotSupported_ThrowsIllegalStateException(
            eu.europa.esig.dss.enumerations.DigestAlgorithm.RIPEMD160);
  }

  @Test
  public void getDigestAlgorithm_WhenDigestAlgorithmIsShake128_ThrowsIllegalStateException() {
    getDigestAlgorithm_WhenDigestAlgorithmIsNotSupported_ThrowsIllegalStateException(
            eu.europa.esig.dss.enumerations.DigestAlgorithm.SHAKE128);
  }

  @Test
  public void getDigestAlgorithm_WhenDigestAlgorithmIsShake256_ThrowsIllegalStateException() {
    getDigestAlgorithm_WhenDigestAlgorithmIsNotSupported_ThrowsIllegalStateException(
            eu.europa.esig.dss.enumerations.DigestAlgorithm.SHAKE256);
  }

  @Test
  public void getDigestAlgorithm_WhenDigestAlgorithmIsShake256_512_ThrowsIllegalStateException() {
    getDigestAlgorithm_WhenDigestAlgorithmIsNotSupported_ThrowsIllegalStateException(
            eu.europa.esig.dss.enumerations.DigestAlgorithm.SHAKE256_512);
  }

  @Test
  public void getDigestAlgorithm_WhenDigestAlgorithmIsWhirlpool_ThrowsIllegalStateException() {
    getDigestAlgorithm_WhenDigestAlgorithmIsNotSupported_ThrowsIllegalStateException(
            eu.europa.esig.dss.enumerations.DigestAlgorithm.WHIRLPOOL);
  }

  // TODO: Replace with @ParameterizedTest when DD4J is migrated to JUnit 5
  private void getDigestAlgorithm_WhenDigestAlgorithmIsNotSupported_ThrowsIllegalStateException(
          eu.europa.esig.dss.enumerations.DigestAlgorithm digestAlgorithm
  ) {
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    TimeStampToken timeStampToken = mock(TimeStampToken.class);
    doReturn(timeStampToken).when(cadesTimestamp).getTimeStampToken();
    TimeStampTokenInfo timeStampTokenInfo = mock(TimeStampTokenInfo.class);
    doReturn(timeStampTokenInfo).when(timeStampToken).getTimeStampInfo();
    ASN1ObjectIdentifier objectIdentifier = new ASN1ObjectIdentifier(digestAlgorithm.getOid());
    doReturn(objectIdentifier).when(timeStampTokenInfo).getMessageImprintAlgOID();
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp);

    IllegalStateException caughtException = assertThrows(
            IllegalStateException.class,
            asicContainerTimestamp::getDigestAlgorithm
    );

    assertThat(caughtException.getMessage(), equalTo(
            "Unrecognizable digest algorithm with OID: " + digestAlgorithm.getOid()
    ));
    verify(cadesTimestamp).getTimeStampToken();
    verify(timeStampToken).getTimeStampInfo();
    verify(timeStampTokenInfo).getMessageImprintAlgOID();
    verifyNoMoreInteractions(cadesTimestamp, timeStampToken, timeStampTokenInfo);
  }

  @Test
  public void getUniqueId_WhenExistingTimestampTokenIsLoaded_ReturnsExpectedIdString() {
    CadesTimestamp cadesTimestamp = new CadesTimestamp(new FileDocument("src/test/resources/testFiles/tst/timestamp.tst"));
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp);

    String result = asicContainerTimestamp.getUniqueId();

    assertThat(result, equalTo("T-E25DFE59160F01A14590688845BCEEB1BD1D41EF5CF8D984B841CED71C8F3038"));
  }

}
