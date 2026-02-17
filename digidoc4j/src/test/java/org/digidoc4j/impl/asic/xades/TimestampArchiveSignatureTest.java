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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TimestampArchiveSignatureTest extends AbstractTest {

    @TempDir
    Path tmpDir;

    @Test
    void getProfile_returnsLTA() throws IOException {
        Container container = TestDataBuilderUtil.createContainerWithFile(tmpDir, Container.DocumentType.ASICE);
        AsicESignature asiceSignature = (AsicESignature) TestDataBuilderUtil.signContainer(container, SignatureProfile.LTA);
        LongTermArchiveSignature timestampArchiveSignature = (LongTermArchiveSignature) asiceSignature.getOrigin();

        SignatureProfile profile = timestampArchiveSignature.getProfile();

        assertEquals(SignatureProfile.LTA, profile);
    }

}
