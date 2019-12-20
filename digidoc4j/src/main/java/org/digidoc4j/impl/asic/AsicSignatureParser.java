/* DigiDoc4J library
 *
 * This software is released under either the GNU Library General Public
 * License (see LICENSE.LGPL).
 *
 * Note that the only valid version of the LGPL license as far as this
 * project is concerned is the original GNU Library General Public License
 * Version 2.1, February 1999
 */

package org.digidoc4j.impl.asic;

import eu.europa.esig.dss.model.DSSDocument;
import org.digidoc4j.Configuration;
import org.digidoc4j.impl.asic.xades.XadesSignature;
import org.digidoc4j.impl.asic.xades.XadesSignatureParser;
import org.digidoc4j.impl.asic.xades.XadesValidationReportGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class AsicSignatureParser {

    private final static Logger logger = LoggerFactory.getLogger(AsicSignatureParser.class);

    private final List<DSSDocument> detachedContents;
    private final Configuration configuration;
    private final XadesSignatureParser xadesSignatureParser = new XadesSignatureParser();

    public AsicSignatureParser(List<DSSDocument> detachedContents, Configuration configuration) {
        this.configuration = configuration;
        this.detachedContents = detachedContents;
    }

    public XadesSignature parse(DSSDocument xadesDocument) {
        logger.debug("Parsing signature from xades document");
        return createXadesSignature(xadesDocument);
    }

    private XadesSignature createXadesSignature(DSSDocument xadesDocument) {
        XadesValidationReportGenerator xadesReportGenerator = new XadesValidationReportGenerator(xadesDocument, detachedContents, configuration);
        return xadesSignatureParser.parse(xadesReportGenerator);
    }
}
