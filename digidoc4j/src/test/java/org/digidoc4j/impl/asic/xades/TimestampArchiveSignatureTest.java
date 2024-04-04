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
import org.digidoc4j.impl.asic.asice.AsicESignature;
import org.digidoc4j.test.util.TestDataBuilderUtil;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;

public class TimestampArchiveSignatureTest extends AbstractTest {

    @Rule
    public TemporaryFolder tmpDir = new TemporaryFolder();

    @Test
    public void getProfile_returnsLTA() throws IOException {
        Container container = TestDataBuilderUtil.createContainerWithFile(tmpDir, Container.DocumentType.ASICE);
        AsicESignature asiceSignature = (AsicESignature) TestDataBuilderUtil.signContainer(container, SignatureProfile.LTA);
        TimestampArchiveSignature timestampArchiveSignature = (TimestampArchiveSignature) asiceSignature.getOrigin();

        SignatureProfile profile = timestampArchiveSignature.getProfile();

        Assert.assertEquals(SignatureProfile.LTA, profile);
    }

}
