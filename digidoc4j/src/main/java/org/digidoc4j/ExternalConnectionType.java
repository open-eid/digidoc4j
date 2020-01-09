package org.digidoc4j;

import org.apache.commons.lang3.tuple.Pair;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import static org.digidoc4j.ConfigurationParameter.*;

public enum ExternalConnectionType {

    TSL(
            Pair.of(HttpProxyHost, TslHttpProxyHost),
            Pair.of(HttpProxyPort, TslHttpProxyPort),
            Pair.of(HttpsProxyHost, TslHttpsProxyHost),
            Pair.of(HttpsProxyPort, TslHttpsProxyPort),
            Pair.of(HttpProxyUser, TslHttpProxyUser),
            Pair.of(HttpProxyPassword, TslHttpProxyPassword),
            Pair.of(SslKeystoreType, TslSslKeystoreType),
            Pair.of(SslTruststoreType, TslSslTruststoreType),
            Pair.of(SslKeystorePath, TslSslKeystorePath),
            Pair.of(SslKeystorePassword, TslSslKeystorePassword),
            Pair.of(SslTruststorePath, TslSslTruststorePath),
            Pair.of(SslTruststorePassword, TslSslTruststorePassword),
            Pair.of(SslProtocol, TslSslProtocol),
            Pair.of(SupportedSslProtocols, TslSupportedSslProtocols),
            Pair.of(SupportedSslCipherSuites, TslSupportedSslCipherSuites)
    ),

    OCSP(
            Pair.of(HttpProxyHost, OcspHttpProxyHost),
            Pair.of(HttpProxyPort, OcspHttpProxyPort),
            Pair.of(HttpsProxyHost, OcspHttpsProxyHost),
            Pair.of(HttpsProxyPort, OcspHttpsProxyPort),
            Pair.of(HttpProxyUser, OcspHttpProxyUser),
            Pair.of(HttpProxyPassword, OcspHttpProxyPassword),
            Pair.of(SslKeystoreType, OcspSslKeystoreType),
            Pair.of(SslTruststoreType, OcspSslTruststoreType),
            Pair.of(SslKeystorePath, OcspSslKeystorePath),
            Pair.of(SslKeystorePassword, OcspSslKeystorePassword),
            Pair.of(SslTruststorePath, OcspSslTruststorePath),
            Pair.of(SslTruststorePassword, OcspSslTruststorePassword),
            Pair.of(SslProtocol, OcspSslProtocol),
            Pair.of(SupportedSslProtocols, OcspSupportedSslProtocols),
            Pair.of(SupportedSslCipherSuites, OcspSupportedSslCipherSuites)
    ),

    TSP(
            Pair.of(HttpProxyHost, TspHttpProxyHost),
            Pair.of(HttpProxyPort, TspHttpProxyPort),
            Pair.of(HttpsProxyHost, TspHttpsProxyHost),
            Pair.of(HttpsProxyPort, TspHttpsProxyPort),
            Pair.of(HttpProxyUser, TspHttpProxyUser),
            Pair.of(HttpProxyPassword, TspHttpProxyPassword),
            Pair.of(SslKeystoreType, TspSslKeystoreType),
            Pair.of(SslTruststoreType, TspSslTruststoreType),
            Pair.of(SslKeystorePath, TspSslKeystorePath),
            Pair.of(SslKeystorePassword, TspSslKeystorePassword),
            Pair.of(SslTruststorePath, TspSslTruststorePath),
            Pair.of(SslTruststorePassword, TspSslTruststorePassword),
            Pair.of(SslProtocol, TspSslProtocol),
            Pair.of(SupportedSslProtocols, TspSupportedSslProtocols),
            Pair.of(SupportedSslCipherSuites, TspSupportedSslCipherSuites)
    ),

    AIA(
            Pair.of(HttpProxyHost, AiaHttpProxyHost),
            Pair.of(HttpProxyPort, AiaHttpProxyPort),
            Pair.of(HttpsProxyHost, AiaHttpsProxyHost),
            Pair.of(HttpsProxyPort, AiaHttpsProxyPort),
            Pair.of(HttpProxyUser, AiaHttpProxyUser),
            Pair.of(HttpProxyPassword, AiaHttpProxyPassword),
            Pair.of(SslKeystoreType, AiaSslKeystoreType),
            Pair.of(SslTruststoreType, AiaSslTruststoreType),
            Pair.of(SslKeystorePath, AiaSslKeystorePath),
            Pair.of(SslKeystorePassword, AiaSslKeystorePassword),
            Pair.of(SslTruststorePath, AiaSslTruststorePath),
            Pair.of(SslTruststorePassword, AiaSslTruststorePassword),
            Pair.of(SslProtocol, AiaSslProtocol),
            Pair.of(SupportedSslProtocols, AiaSupportedSslProtocols),
            Pair.of(SupportedSslCipherSuites, AiaSupportedSslCipherSuites)
    );

    private final Map<ConfigurationParameter, ConfigurationParameter> genericToSpecificParameterMap;

    ExternalConnectionType(Pair<ConfigurationParameter, ConfigurationParameter>... parameterMappings) {
        genericToSpecificParameterMap = Arrays.stream(parameterMappings).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    ConfigurationParameter mapToSpecificParameter(ConfigurationParameter genericParameter) {
        ConfigurationParameter specificParameter = genericToSpecificParameterMap.get(genericParameter);
        if (specificParameter == null) {
            throw new IllegalArgumentException("No mappings found for " + genericParameter + " in " + this);
        }
        return specificParameter;
    }

}
