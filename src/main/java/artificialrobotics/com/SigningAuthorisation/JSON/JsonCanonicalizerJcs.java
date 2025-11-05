package artificialrobotics.com.SigningAuthorisation.json;

import java.math.BigDecimal;
import java.util.*;

/**
 * Minimaler JSON Canonicalizer nach JCS-Ideen (RFC 8785, pragmatische Teilmenge).
 *
 * Merkmale:
 *  - Objekt-Schlüssel lexikographisch nach Unicode Code-Points sortiert
 *  - Arrays bleiben in Originalreihenfolge
 *  - Strings werden JSON-escaped ausgegeben
 *  - Zahlen werden über BigDecimal normalisiert:
 *      * keine Exponentendarstellung
 *      * keine führenden +/-
 *      * keine überflüssigen Nullen (stripTrailingZeros)
 *      * "-0" -> "0"
 *  - true/false/null bleiben erhalten
 *
 * Hinweis:
 *  Diese Implementierung deckt typische Payloads stabil ab, ist aber bewusst
 *  "pragmatisch". Für 100% RFC-8785-Konformität in allen Randfällen ggf. eine
 *  dedizierte JCS-Bibliothek einsetzen.
 */
public final class JsonCanonicalizerJcs {

    private JsonCanonicalizerJcs() {}

    /** Kanonisiert ein JSON-Document (Objekt oder Array) zu einer stabilen String-Repräsentation. */
    public static String canonicalize(String json) {
        Parser p = new Parser(json);
        Object v = p.parseAny();
        p.skipWs();
        if (!p.eof()) throw new IllegalArgumentException("Trailing characters after JSON payload");
        StringBuilder sb = new StringBuilder(json.length());
        writeCanonical(v, sb);
        return sb.toString();
    }

    /* ====================== Writer ====================== */

    private static void writeCanonical(Object v, StringBuilder sb) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof Boolean b) { sb.append(b ? "true" : "false"); return; }
        if (v instanceof String s) { writeString(s, sb); return; }
        if (v instanceof BigDecimal bd) { sb.append(numberToString(bd)); return; }
        if (v instanceof List<?> list) {
            sb.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(',');
                writeCanonical(list.get(i), sb);
            }
            sb.append(']');
            return;
        }
        if (v instanceof Map<?, ?> map) {
            // Schlüssel sortieren (Unicode Code-Point Reihenfolge)
            List<String> keys = new ArrayList<>();
            for (Object k : map.keySet()) keys.add((String) k);
            Collections.sort(keys);
            sb.append('{');
            for (int i = 0; i < keys.size(); i++) {
                if (i > 0) sb.append(',');
                String k = keys.get(i);
                writeString(k, sb);
                sb.append(':');
                writeCanonical(map.get(k), sb);
            }
            sb.append('}');
            return;
        }
        // Fallback: als String
        writeString(String.valueOf(v), sb);
    }

    private static void writeString(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (ch < 0x20) sb.append(String.format("\\u%04x", (int) ch));
                    else sb.append(ch);
                }
            }
        }
        sb.append('"');
    }

    private static String numberToString(BigDecimal bd) {
        bd = bd.stripTrailingZeros();
        String s = bd.toPlainString();
        // "-0" -> "0"
        if (s.startsWith("-0") && (s.length() == 2 || (s.length() > 2 && s.charAt(2) == '.'))) {
            s = s.substring(1);
        }
        return s;
    }

    /* ====================== Parser ====================== */

    /**
     * Sehr einfacher JSON-Parser in ein Intermediate Model:
     *  - Objekt: Map<String,Object> (LinkedHashMap in Eingabereihenfolge)
     *  - Array:  List<Object>
     *  - Zahl:   BigDecimal
     *  - String: String
     *  - true/false/null → Boolean/Null
     */
    static final class Parser {
        final String s; int i=0;
        Parser(String s){ this.s=s; }
        boolean eof(){ return i>=s.length(); }
        void skipWs(){ while(i<s.length() && Character.isWhitespace(s.charAt(i))) i++; }

        Object parseAny() {
            skipWs(); if (eof()) throw err("Unexpected end");
            char c = s.charAt(i);
            return switch (c) {
                case '{' -> parseObj();
                case '[' -> parseArr();
                case '"' -> parseString();
                case 't' -> { expect("true"); yield Boolean.TRUE; }
                case 'f' -> { expect("false"); yield Boolean.FALSE; }
                case 'n' -> { expect("null"); yield null; }
                default -> parseNumber();
            };
        }

        Map<String,Object> parseObj() {
            expect('{'); skipWs();
            Map<String,Object> m = new LinkedHashMap<>();
            if (peek('}')) { i++; return m; }
            while (true) {
                String k = parseString(); skipWs(); expect(':'); skipWs();
                Object v = parseAny(); m.put(k,v); skipWs();
                if (peek('}')) { i++; break; }
                expect(','); skipWs();
            }
            return m;
        }

        List<Object> parseArr() {
            expect('['); skipWs();
            List<Object> l = new ArrayList<>();
            if (peek(']')) { i++; return l; }
            while (true) {
                l.add(parseAny()); skipWs();
                if (peek(']')) { i++; break; }
                expect(','); skipWs();
            }
            return l;
        }

        String parseString() {
            expect('"'); StringBuilder sb = new StringBuilder();
            while (!eof()) {
                char c = s.charAt(i++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (eof()) throw err("Bad escape");
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"','\\','/' -> sb.append(e);
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (i+4 > s.length()) throw err("Bad \\u escape");
                            String hex = s.substring(i, i+4);
                            i += 4;
                            sb.append((char) Integer.parseInt(hex, 16));
                        }
                        default -> throw err("Bad escape: \\"+e);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw err("Unterminated string");
        }

        BigDecimal parseNumber() {
            int start = i;
            if (s.charAt(i) == '-') i++;
            int intStart = i;
            while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            boolean hasInt = i > intStart;
            boolean hasFrac = false, hasExp = false;
            if (i < s.length() && s.charAt(i) == '.') {
                hasFrac = true; i++;
                int fracStart = i;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
                if (i == fracStart) throw err("Invalid fraction");
            }
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                hasExp = true; i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                int expStart = i;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
                if (i == expStart) throw err("Invalid exponent");
            }
            if (!hasInt) throw err("Invalid number");
            String num = s.substring(start, i);
            try {
                return new BigDecimal(num);
            } catch (NumberFormatException ex) {
                throw err("Bad number: " + num);
            }
        }

        void expect(char c){ if (eof() || s.charAt(i)!=c) throw err("Expected '"+c+"'"); i++; }
        void expect(String lit){ for (int j=0;j<lit.length();j++) expect(lit.charAt(j)); }
        boolean peek(char c){ return !eof() && s.charAt(i)==c; }
        IllegalArgumentException err(String m){ return new IllegalArgumentException(m+" at pos "+i); }
    }
}