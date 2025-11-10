package artificialrobotics.com.SigningAuthorisation.json;

import java.math.BigDecimal;
import java.util.*;

/**
 * JSON Canonicalizer angelehnt an RFC 8785 (JCS – JSON Canonicalization Scheme).
 *
 * Eigenschaften:
 *  - Objekt-Schlüssel werden lexikographisch nach UTF-16 Code Units sortiert
 *  - Arrays behalten ihre ursprüngliche Reihenfolge
 *  - Strings werden JSON-konform escaped; alle U+0000..U+001F stets als \\u00xx (keine Kurz-Escapes)
 *  - Zahlen werden via BigDecimal minimal dargestellt:
 *      * keine Exponentendarstellung (toPlainString)
 *      * stripTrailingZeros
 *      * "-0" → "0"
 *  - true/false/null bleiben erhalten
 *
 * Parser (streng nach JSON):
 *  - Führende Nullen im Integerteil sind nicht erlaubt (außer "0" selbst)
 *  - Zahlen werden als BigDecimal geparst (keine NaN/Infinity)
 *
 * Hinweis:
 *  Diese Implementierung zielt auf JCS-Konformität für typische Payloads.
 *  Für vollständige Randfallabdeckung kann eine dedizierte JCS-Referenzbibliothek eingesetzt werden.
 */
public final class JsonCanonicalizerJcs {

    private JsonCanonicalizerJcs() {}

    /** Kanonisiert ein JSON-Dokument (Objekt oder Array) zu einer stabilen String-Repräsentation. */
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
            // Schlüssel sortieren (UTF-16 Code Unit Reihenfolge)
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
        // Fallback (sollte nicht vorkommen): als String
        writeString(String.valueOf(v), sb);
    }

    /**
     * String-Ausgabe: JSON-escaping.
     * JCS fordert: alle Steuerzeichen U+0000..U+001F als \\u00xx.
     * Zudem werden Anführungszeichen und Backslash per \" bzw. \\ escaped.
     */
    private static void writeString(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '"')  { sb.append("\\\""); continue; }
            if (ch == '\\') { sb.append("\\\\"); continue; }
            if (ch < 0x20) {
                // Immer \\u00xx (keine Kurz-Escapes), gem. RFC 8785
                sb.append("\\u").append(hex4(ch));
                continue;
            }
            sb.append(ch);
        }
        sb.append('"');
    }

    /** Wandelt einen char (0..0xFFFF) in vierstellige Hex (lowercase) um. */
    private static String hex4(int ch) {
        String h = Integer.toHexString(ch);
        return "0000".substring(h.length()) + h;
    }

    /**
     * Zahlen-Ausgabe in Minimalform:
     *  - stripTrailingZeros
     *  - toPlainString (keine Exponentendarstellung)
     *  - "-0" → "0"
     */
    private static String numberToString(BigDecimal bd) {
        bd = bd.stripTrailingZeros();
        String s = bd.toPlainString();
        // "-0" oder "-0.xxx" → "0" bzw. "0.xxx"
        if (s.startsWith("-0")) {
            if (s.length() == 2) {
                // "-0"
                return "0";
            }
            if (s.length() > 2 && s.charAt(2) == '.') {
                // "-0.xxx" → ohne Minus
                return s.substring(1);
            }
        }
        return s;
    }

    /* ====================== Parser ====================== */

    /**
     * Einfacher JSON-Parser in ein Intermediate Model:
     *  - Objekt: Map<String,Object> (LinkedHashMap in Eingabereihenfolge; Duplikate überschreiben vorangehende)
     *  - Array:  List<Object>
     *  - Zahl:   BigDecimal (strenges JSON, keine führenden Nullen, keine NaN/Infinity)
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
                            try {
                                sb.append((char) Integer.parseInt(hex, 16));
                            } catch (NumberFormatException ex) {
                                throw err("Bad \\u escape digits");
                            }
                        }
                        default -> throw err("Bad escape: \\"+e);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw err("Unterminated string");
        }

        /**
         * Zahl-Parser (streng nach JSON):
         *  - Optionales Minus
         *  - Integerteil: entweder "0" ODER keine führende 0
         *  - Optional Fraction: '.' DIGITS+
         *  - Optional Exponent: [eE] ['+'|'-']? DIGITS+
         *  - Übergabe an BigDecimal
         */
        BigDecimal parseNumber() {
            int start = i;

            // optional '-'
            if (s.charAt(i) == '-') i++;

            // Integerteil
            if (i >= s.length() || !Character.isDigit(s.charAt(i))) {
                throw err("Invalid number");
            }
            if (s.charAt(i) == '0') {
                i++;
                // keine weiteren Ziffern direkt nach '0' erlaubt (außer '.' oder 'e/E')
                if (i < s.length() && Character.isDigit(s.charAt(i))) {
                    throw err("Leading zero in integer part");
                }
            } else {
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
            }

            // Fraction
            if (i < s.length() && s.charAt(i) == '.') {
                i++;
                int fracStart = i;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
                if (i == fracStart) throw err("Invalid fraction");
            }

            // Exponent
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                int expStart = i;
                while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
                if (i == expStart) throw err("Invalid exponent");
            }

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
