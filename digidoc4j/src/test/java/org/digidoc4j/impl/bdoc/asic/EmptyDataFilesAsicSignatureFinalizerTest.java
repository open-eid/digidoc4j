package org.digidoc4j.impl.bdoc.asic;

import org.digidoc4j.DataFile;
import org.digidoc4j.SignatureParameters;
import org.digidoc4j.impl.EmptyDataFilesSignatureFinalizerTest;
import org.digidoc4j.impl.SignatureFinalizer;
import org.digidoc4j.impl.asic.AsicSignatureFinalizer;

import java.util.List;

public class EmptyDataFilesAsicSignatureFinalizerTest extends EmptyDataFilesSignatureFinalizerTest {

    @Override
    protected SignatureFinalizer createSignatureFinalizerWithDataFiles(List<DataFile> dataFiles) {
        return new AsicSignatureFinalizer(dataFiles, new SignatureParameters(), configuration);
    }

}
