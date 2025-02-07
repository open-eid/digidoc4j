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

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Hex;
import org.digidoc4j.X509Cert;
import org.digidoc4j.exceptions.TechnicalException;
import org.digidoc4j.test.TestConstants;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.digidoc4j.test.matcher.CommonMatchers.equalToIsoDate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

public class CadesTimestampTest {

  @Test
  public void createInstance_WhenWrappedDocumentIsMock_DocumentIsWrappedWithoutParsingIt() {
    DSSDocument timestampDocument = mock(DSSDocument.class);
    CadesTimestamp cadesTimestamp = new CadesTimestamp(timestampDocument);

    DSSDocument result = cadesTimestamp.getTimestampDocument();

    assertThat(result, sameInstance(timestampDocument));
    verifyNoInteractions(timestampDocument);
  }

  @Test
  public void getCertificate_WhenDocumentIsNotParsable_ThrowsException() {
    DSSDocument timestampDocument = new InMemoryDocument("Not timestamp!".getBytes(StandardCharsets.UTF_8));
    CadesTimestamp cadesTimestamp = new CadesTimestamp(timestampDocument);

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            cadesTimestamp::getCertificate
    );

    assertThat(caughtException.getMessage(), equalTo("Failed to parse TimeStampToken"));
  }

  @Test
  public void getCertificate_WhenDocumentIsExistingLoadedTimestamp_ReturnsCertificateWithExpectedFields() {
    DSSDocument timestampDocument = new FileDocument("src/test/resources/testFiles/tst/timestamp.tst");
    CadesTimestamp cadesTimestamp = new CadesTimestamp(timestampDocument);

    X509Cert result = cadesTimestamp.getCertificate();

    assertThat(result, notNullValue());
    assertThat(result.getSerial(), equalTo("4eacfb6c23fc5b8e540596bbb73b534c"));
    assertThat(result.getSubjectName(X509Cert.SubjectName.CN), equalTo(TestConstants.DEMO_SK_TSA_2014_CN));
    assertThat(result.getSubjectName(X509Cert.SubjectName.C), equalTo("EE"));
  }

  @Test
  public void getCreationTime_WhenDocumentIsNotParsable_ThrowsException() {
    DSSDocument timestampDocument = new InMemoryDocument("Not timestamp!".getBytes(StandardCharsets.UTF_8));
    CadesTimestamp cadesTimestamp = new CadesTimestamp(timestampDocument);

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            cadesTimestamp::getCreationTime
    );

    assertThat(caughtException.getMessage(), equalTo("Failed to parse TimeStampToken"));
  }

  @Test
  public void getCreationTime_WhenDocumentIsExistingLoadedTimestamp_ReturnsExpectedCreationTime() {
    DSSDocument timestampDocument = new FileDocument("src/test/resources/testFiles/tst/timestamp.tst");
    CadesTimestamp cadesTimestamp = new CadesTimestamp(timestampDocument);

    Date result = cadesTimestamp.getCreationTime();

    assertThat(result, equalToIsoDate("2017-11-23T11:25:54Z"));
  }

  @Test
  public void getTimeStampToken_WhenDocumentIsNotParsable_ThrowsException() {
    DSSDocument timestampDocument = new InMemoryDocument("Not timestamp!".getBytes(StandardCharsets.UTF_8));
    CadesTimestamp cadesTimestamp = new CadesTimestamp(timestampDocument);

    TechnicalException caughtException = assertThrows(
            TechnicalException.class,
            cadesTimestamp::getTimeStampToken
    );

    assertThat(caughtException.getMessage(), equalTo("Failed to parse TimeStampToken"));
  }

  @Test
  public void getTimeStampToken_WhenDocumentIsExistingLoadedTimestamp_ReturnsTimeStampTokenWithExpectedFeatures() {
    DSSDocument timestampDocument = new FileDocument("src/test/resources/testFiles/tst/timestamp.tst");
    CadesTimestamp cadesTimestamp = new CadesTimestamp(timestampDocument);

    TimeStampToken result = cadesTimestamp.getTimeStampToken();

    assertThat(result, notNullValue());
    assertThat(result.getSID(), notNullValue());
    assertThat(result.getSID().getIssuer().toString(), containsString("TEST of EE Certification Centre Root CA"));
    assertThat(result.getSID().getSerialNumber(), equalTo(new BigInteger("104577958183480553559561041502222897996")));
    assertThat(result.getTimeStampInfo(), notNullValue());
    assertThat(result.getTimeStampInfo().getGenTime(), equalToIsoDate("2017-11-23T11:25:54Z"));
    assertThat(result.getTimeStampInfo().getSerialNumber(), equalTo(new BigInteger("6442984656785638527")));
    assertThat(result.getTimeStampInfo().getMessageImprintAlgOID().toString(), equalTo("2.16.840.1.101.3.4.2.1"));
    assertArrayEquals(
            Hex.decode("46a0eab6a8b7ad3b168f4eebad67399004c0648c3b4f55c73ff34f2c2174e515"),
            result.getTimeStampInfo().getMessageImprintDigest()
    );
  }

}
