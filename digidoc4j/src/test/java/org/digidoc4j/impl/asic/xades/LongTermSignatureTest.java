/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.xades;

import org.digidoc4j.AbstractTest;
import org.digidoc4j.Container;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.X509Cert;
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.test.TestAssert;
import org.digidoc4j.test.TestConstants;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class LongTermSignatureTest extends AbstractTest {

    @Rule
    public TemporaryFolder tmpDir = new TemporaryFolder();

    @Test
    public void getProfile_returnsLT() throws IOException {
        LongTermSignature longTermSignature = createTimestampSignature();

        SignatureProfile profile = longTermSignature.getProfile();

        Assert.assertEquals(SignatureProfile.LT, profile);
    }

    @Test
    public void getTimeStampTokenCertificate_certificateExists_ReturnsCertificate() throws IOException {
        LongTermSignature longTermSignature = createTimestampSignature();

        X509Cert timeStampTokenCertificate = longTermSignature.getTimeStampTokenCertificate();

        Assert.assertEquals(TestConstants.DEMO_TSA_CN, timeStampTokenCertificate.getSubjectName(X509Cert.SubjectName.CN));
    }

    @Test
    public void getTimeStampCreationTime_timeStampInfoExists_creationTimeIsRecent() throws IOException {
        Instant startTime = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        LongTermSignature longTermSignature = createTimestampSignature();

        Date timeStampCreationTime = longTermSignature.getTimeStampCreationTime();

        TestAssert.assertTimeBetweenNotBeforeAndNow(timeStampCreationTime, startTime, Duration.ofMinutes(1));
    }

    private LongTermSignature createTimestampSignature() throws IOException {
        Container container = TestDataBuilderUtil.createContainerWithFile(tmpDir, Container.DocumentType.ASICE);
        AsicESignature asiceSignature = (AsicESignature) TestDataBuilderUtil.signContainer(container, SignatureProfile.LT);
        return (LongTermSignature) asiceSignature.getOrigin();
    }
}
