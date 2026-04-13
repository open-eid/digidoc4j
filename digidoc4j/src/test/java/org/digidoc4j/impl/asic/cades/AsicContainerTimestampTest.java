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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

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
  void createInstance_WhenCadesTimestampIsNull_ThrowsNullPointerException() {
    assertThrows(
            NullPointerException.class,
            () -> createDefaultAsicContainerTimestampWith(null)
    );
  }

  @Test
  void getCadesTimestamp_WhenCadesTimestampHasBeenProvidedOnCreation_ReturnsSameInstance() {
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp);

    CadesTimestamp result = asicContainerTimestamp.getCadesTimestamp();

    assertThat(result, sameInstance(cadesTimestamp));
    verifyNoInteractions(cadesTimestamp);
  }

  @Test
  void getArchiveManifest_WhenManifestHasNotBeenProvidedOnCreation_ReturnsNull() {
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp);

    AsicArchiveManifest result = asicContainerTimestamp.getArchiveManifest();

    assertThat(result, nullValue());
    verifyNoInteractions(cadesTimestamp);
  }

  @Test
  void getArchiveManifest_WhenManifestHasBeenSetToNullOnCreation_ReturnsNull() {
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp, null);

    AsicArchiveManifest result = asicContainerTimestamp.getArchiveManifest();

    assertThat(result, nullValue());
    verifyNoInteractions(cadesTimestamp);
  }

  @Test
  void getArchiveManifest_WhenManifestHasBeenProvidedOnCreation_ReturnsSameInstance() {
    CadesTimestamp cadesTimestamp = mock(CadesTimestamp.class);
    AsicArchiveManifest asicArchiveManifest = mock(AsicArchiveManifest.class);
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp, asicArchiveManifest);

    AsicArchiveManifest result = asicContainerTimestamp.getArchiveManifest();

    assertThat(result, sameInstance(asicArchiveManifest));
    verifyNoInteractions(cadesTimestamp, asicArchiveManifest);
  }

  @Test
  void getCertificate_WhenCadesTimestampWrappedIntoAsicContainerTimestamp_RequestIsDelegatedToWrappedCadesTimestamp() {
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
  void getCreationTime_WhenCadesTimestampWrappedIntoAsicContainerTimestamp_RequestIsDelegatedToWrappedCadesTimestamp() {
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
  void getTimeStampToken_WhenCadesTimestampWrappedIntoAsicContainerTimestamp_RequestIsDelegatedToWrappedCadesTimestamp() {
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

  @ParameterizedTest
  @EnumSource(DigestAlgorithm.class)
  void getDigestAlgorithm_WhenDigestAlgorithmIsSupported_ReturnsDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
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

  @ParameterizedTest
  @EnumSource(
          value = eu.europa.esig.dss.enumerations.DigestAlgorithm.class,
          names = {"MD2", "MD5", "RIPEMD160", "SHAKE128", "SHAKE256", "SHAKE256_512", "WHIRLPOOL"}
  )
  void getDigestAlgorithm_WhenDigestAlgorithmIsNotSupported_ThrowsIllegalStateException(
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
  void getUniqueId_WhenExistingTimestampTokenIsLoaded_ReturnsExpectedIdString() {
    CadesTimestamp cadesTimestamp = new CadesTimestamp(new FileDocument("src/test/resources/testFiles/tst/timestamp.tst"));
    T asicContainerTimestamp = createDefaultAsicContainerTimestampWith(cadesTimestamp);

    String result = asicContainerTimestamp.getUniqueId();

    assertThat(result, equalTo("T-E25DFE59160F01A14590688845BCEEB1BD1D41EF5CF8D984B841CED71C8F3038"));
  }

}
