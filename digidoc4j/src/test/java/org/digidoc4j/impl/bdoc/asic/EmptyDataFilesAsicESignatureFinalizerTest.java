package org.digidoc4j.impl.bdoc.asic;

import org.digidoc4j.DataFile;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.impl.EmptyDataFilesSignatureFinalizerTest;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.impl.asic.asice.AsicESignatureFinalizer;

import java.util.List;

public class EmptyDataFilesAsicESignatureFinalizerTest extends EmptyDataFilesSignatureFinalizerTest {

    @Override
    protected SignatureFinalizer createSignatureFinalizerWithDataFiles(List<DataFile> dataFiles) {
        return new AsicESignatureFinalizer(dataFiles, new SignatureParameters(), configuration);
    }

}
