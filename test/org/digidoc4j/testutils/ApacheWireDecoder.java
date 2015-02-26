package org.digidoc4j.testutils;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.ArrayUtils;
import org.bouncycastle.util.encoders.Hex;


/**
 * This utility simplifies debugging by decoding HTTP traffic logs in the 
 * DigiDoc4J log file. For example, this is useful for decoding OCSP requests
 * and responses as logged by DigiDoc4J (internally, DigiDoc4J uses the "Wire" 
 * class from Apache HTTP Client for encoding). 
 */
public class ApacheWireDecoder {
    public static void main(String[] args) {
        String input;
        if(args.length == 0) {
            input =
                    "0[0x82][0x2]U[\\n]\r\n" + 
                    "[0x1][0x0][0xa0][0x82][0x2]N0[0x82][0x2]J[0x6][0x9]+[0x6][0x1][0x5][0x5][0x7]0[0x1][0x1][0x4][0x82][0x2];0[0x82][0x2]70[0x82][0x1][0x1f][0xa1][0x81][0x86]0[0x81][0x83]1[0xb]0[0x9][0x6][0x3]U[0x4][0x6][0x13][0x2]EE1\"0 [0x6][0x3]U[0x4][\\n]\r\n" + 
                    "[0xc][0x19]AS Sertifitseerimiskeskus1[\\r]0[0xb][0x6][0x3]U[0x4][0xb][0xc][0x4]OCSP1'0%[0x6][0x3]U[0x4][0x3][0xc][0x1e]TEST of SK OCSP RESPONDER 20111[0x18]0[0x16][0x6][0x9]*[0x86]H[0x86][0xf7][\\r][0x1][0x9][0x1][0x16][0x9]pki@sk.ee[0x18][0xf]20150216144450Z0`0^0I0[0x9][0x6][0x5]+[0xe][0x3][0x2][0x1a][0x5][0x0][0x4][0x14]S=;[0xc8][0xf5][0xb1][\\n]\r\n" + 
                    "[0xec][0xc3]|[0xb6]gW[0xbf][0xd9][0x98][0xae][0x93][0x3][0x89][0x4][0x14][0x12][0xf2]Z>[0xea]V[0x1c][0xbf][0xcd][0x6][0xac][0xf1][0xf1]%[0xc9][0xa9]K[0xd4][0x14][0x99][0x2][0x10]$[0xaf][0xec][0xeb][0x12]h[0xd0][0x2]T[0x17][0xf7][0x86][0xed]o[0x1]Y[0x80][0x0][0x18][0xf]20150216144450Z[0xa1]!0[0x1f]0[0x1d][0x6][0x9]+[0x6][0x1][0x5][0x5][0x7]0[0x1][0x2][0x1][0x1][0xff][0x4][\\r]14240978906440[\\r][0x6][0x9]*[0x86]H[0x86][0xf7][\\r][0x1][0x1][0x5][0x5][0x0][0x3][0x82][0x1][0x1][0x0][0xa0][0xff][0xb4][0x8e][0x82][0x12][0xc]!by[0xf9][0x8a][0xbb]@B*[0x0]cU[0xe9]1[0x18][0xb7]h\\n[0xb2][0x1e]4[0x80]'QK[0xc0][0xf2][0x98][0x8f][0xf8][0xf0]H[0x9f]_P[0xac][0x92]{[0x1d][0xc6]([0xcd][0xfe][0x1][0xc1]d[0xbc]l[0xdb][0xc0]9[0xe6]F[0xf3][0x92]8[0xeb][0xd5][0xdc]Y+[0xc2][0xe0][0x8d]p[0x15]Yo[0xe][0xed]be[0xa9]6nd[0xed]JP[0xe8]f[0x1c][0xe1][0x99]:[0xed][0xa5]<xU[0xd7]P[0x9a][0x17][0xb3][0xe6];-[0x85][0xf3]p[0xf6][0xd7][0xee]k[0xb5][0x5]e:K$[0xaf]G[0xe5]H[0xb1][0x1f]%[0xa0]Z[0x11]1y'[\\r]%[0x95][0xaf][0x9c]j>[0x18]Pw[0xc1][0xbe][0xc4][0xe8]BT7X[0xce]fo[0xfd][0x15][0x7][0x18]Ta$A[0x97]L[0x16][0x5]y[0xf][0xc4][0xf3]pJ|~[0xa2][0xc3][0x90][0x8b][0xe5][0xe]f[0xa0][0x92]d*[0xb2][0x8][0xb8][0xc3][0xad][0xa5][0xb6][0x84]>[0x82][0xa3][0x81][0x13]#[0xd7][0x98][0xc7]{N a7[0xc3]R'gt[0x9][0x97][0xd1][0xb2]'\\[0x9b][0x12][0xb6]I[0xea]Uq[0xd0]Q>![0xfc][0x8a][0x99][0x2]:[0xed][0xdf]Eo[0x14]dd[0x9a] b[0xbc][0xb4]BbX[0x84]bS[0xc2][0xca]\r\n" + 
                    "";
            
            System.out.println("No input provided on the command line, using the following sample input:");
            System.out.println();
            System.out.println(input);
            System.out.println();
            System.out.println("Corresponding output is:");
            System.out.println();
        } else if(args.length == 1) {
            input = args[0];
        } else {
            throw new IllegalArgumentException("Please pack the entire input into one command line argument, as whitspace is important in the input");
        }
        
        ApacheWireDecoder decoder = new ApacheWireDecoder();
        System.out.println(Hex.toHexString(decoder.decode(input)));
    }
    
    public byte[] decode(String input) {
        input = removeUnescapedNewlines(input);
        
        List<Byte> result = new ArrayList<>();
        
        for (int pos = 0; pos < input.length(); ) {
            int charactersConsumed = readNextByte(input, pos, result);
            pos += charactersConsumed;
        }
        
        return ArrayUtils.toPrimitive(result.toArray(new Byte[0]));
    }

    protected int readNextByte(String input, int pos, List<Byte> result) {
        if (input.charAt(pos) == '[') {
            return readEscapedByte(input, pos, result);
        }
        return readPlainByte(input, pos, result);
    }

    protected int readPlainByte(String input, int pos, List<Byte> result) {
        result.add((byte) input.charAt(pos));
        return 1;
    }

    protected int readEscapedByte(String input, int pos, List<Byte> result) {
        String bracketContents = extractBracketContents(input, pos);
        return readEscapedByteFromBracketContents(bracketContents, result);
    }

    protected String extractBracketContents(String input, int openingBracket) {
        int closingBracket = input.indexOf(']', openingBracket);
        if(closingBracket == -1) {
            // This is not an escape sequence, but a regular opening bracket
            return ""; 
        }
        
        return input.substring(openingBracket + 1, closingBracket);
    }

    protected int readEscapedByteFromBracketContents(String bracketContents, List<Byte> result) {
        if (bracketContents.equals("\\r")) {
            result.add((byte) '\r');
            return bracketContents.length() + 2;
        } else if (bracketContents.equals("\\n")) {
            result.add((byte) '\n');
            return bracketContents.length() + 2;
        } else if (bracketContents.startsWith("0x")) {
            result.add(decodeHexByte(bracketContents));
            return bracketContents.length() + 2;
        } else {
            // Unfortunately this encoding is nondeterministic: the opening bracket "["
            // can either mean the start of an escape sequence, or it can simply represent
            // the bracket itself. Once we've reached here, we know it is not an escape
            // sequence, so it must be a plain byte. 
            return readPlainByte("[", 0, result);
        }
    }

    protected byte decodeHexByte(String byteInHex) {
        String characterHexCode = byteInHex.substring("0x".length());
        if(characterHexCode.length() == 1) {
            characterHexCode = "0" + characterHexCode;
        }
        return Hex.decode(characterHexCode)[0];
    }

    protected String removeUnescapedNewlines(String input) {
        return input.replaceAll("[\\r\\n]", "");
    }
}
