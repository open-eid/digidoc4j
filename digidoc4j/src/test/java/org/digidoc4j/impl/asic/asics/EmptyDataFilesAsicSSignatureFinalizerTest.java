/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic.asics;

import org.digidoc4j.DataFile;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.impl.EmptyDataFilesSignatureFinalizerTest;
import org.digidoc4j.impl.SignatureFinalizer;

import java.util.List;

class EmptyDataFilesAsicSSignatureFinalizerTest extends EmptyDataFilesSignatureFinalizerTest {

    @Override
    protected SignatureFinalizer createSignatureFinalizerWithDataFiles(List<DataFile> dataFiles) {
        return new AsicSSignatureFinalizer(dataFiles, new SignatureParameters(), configuration);
    }

}
