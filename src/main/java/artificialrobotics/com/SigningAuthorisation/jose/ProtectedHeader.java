package artificialrobotics.com.SigningAuthorisation.jose;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.Base64;

public class ProtectedHeader {

    private final LinkedHashMap<String, Object> header = new LinkedHashMap<>();

    public ProtectedHeader() {}

    public ProtectedHeader(Map<String, Object> base) {
        if (base != null) {
            for (Map.Entry<String, Object> e : base.entrySet()) {
                header.put(e.getKey(), deepCopy(e.getValue()));
            }
        }
        enforceCritForB64False();
    }

    /* ========================= Public API ========================= */

    /** Full copy as Map<String,Object> (deep copied). */
    public Map<String, Object> asObjectMap() {
        LinkedHashMap<String, Object> copy = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : header.entrySet()) {
            copy.put(e.getKey(), deepCopy(e.getValue()));
        }
        return copy;
    }

    /** String representation of all values. */
    public Map<String, String> asStringMap() {
        LinkedHashMap<String, String> map = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : header.entrySet()) {
            map.put(e.getKey(), (e.getValue() == null) ? "null" : String.valueOf(e.getValue()));
        }
        return map;
    }

    /**
     * Set/override a header field.
     *
     * Special handling:
     * - "sigT": value "CURRENT" (case-insensitive) becomes current UTC time (ISO 8601, seconds, 'Z').
     * - "crit": merged additively (duplicates removed).
     * - "sigT" and "sub": automatically added to "crit".
     *
     * Note: "b64" is enforced in "crit" if b64=false is set (RFC 7797).
     */
    public ProtectedHeader put(String key, Object value) {
        if (key == null) return this;

        switch (key) {
            case "sigT" -> {
                Object v = normalizeSigT(value);
                header.put("sigT", v);
                addCritical("sigT");
            }
            case "sub" -> {
                header.put("sub", deepCopy(value));
                addCritical("sub");
            }
            case "crit" -> mergeCrit(value);
            default -> header.put(key, deepCopy(value));
        }

        enforceCritForB64False();
        return this;
    }

    /**
     * Apply overrides from JSON.
     *
     * Special handling:
     * - "crit" is merged additively.
     * - "sigT"="CURRENT" -> current UTC time.
     * - "sigT" and "sub" automatically added to "crit".
     */
    public ProtectedHeader applyOverridesJson(String overridesJson) {
        if (overridesJson == null || overridesJson.isBlank()) return this;
        Object parsed = parseJson(overridesJson.trim());
        if (!(parsed instanceof Map)) {
            throw new IllegalArgumentException("Overrides JSON must be a JSON object at top-level.");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> ov = (Map<String, Object>) parsed;

        for (Map.Entry<String, Object> e : ov.entrySet()) {
            String k = e.getKey();
            Object v = e.getValue();
            if ("crit".equals(k)) {
                mergeCrit(v);
            } else if ("sigT".equals(k)) {
                header.put("sigT", normalizeSigT(v));
                addCritical("sigT");
            } else if ("sub".equals(k)) {
                header.put("sub", deepCopy(v));
                addCritical("sub");
            } else {
                header.put(k, deepCopy(v));
            }
        }

        enforceCritForB64False();
        return this;
    }

    /**
     * Optional FINAL allow-list filter for "crit".
     *
     * Intended use:
     * - Some validators (e.g., DSS profiles) expect a restricted set of crit entries,
     *   such as ["b64","sigT","sigD"] (if present).
     *
     * Semantics:
     * - If allowList is null/empty: no changes (legacy behavior).
     * - If "crit" does not exist: no changes.
     * - Keeps only entries that are contained in allowList.
     * - Additionally enforces "if present": only keeps an entry if the corresponding
     *   claim exists in the header (special-case: "b64" only counts as present if b64=false).
     * - Removes "crit" if it becomes empty.
     *
     * Note: After filtering, RFC 7797 compliance is still ensured:
     *       if b64=false is set, "b64" will be (re-)added to crit by enforceCritForB64False().
     *       Therefore, if you use b64=false and also want strict allow-listing, ensure "b64"
     *       is included in allowList.
     */
    public ProtectedHeader applyCritAllowList(Collection<String> allowList) {
        if (allowList == null || allowList.isEmpty()) return this;

        Object c = header.get("crit");
        if (c == null) return this;

        // Normalize allow list
        Set<String> allowed = new LinkedHashSet<>();
        for (String s : allowList) {
            if (s == null) continue;
            String t = s.trim();
            if (!t.isEmpty()) allowed.add(t);
        }
        if (allowed.isEmpty()) return this;

        List<String> current = currentCritList();
        List<String> filtered = new ArrayList<>();

        for (String name : current) {
            if (name == null) continue;
            if (!allowed.contains(name)) continue;

            // "if present" rule: only keep if claim exists in header
            boolean present = header.containsKey(name);

            // special-case b64: only meaningful/present if b64=false
            if ("b64".equals(name)) {
                present = Boolean.FALSE.equals(header.get("b64"));
            }

            if (!present) continue;

            if (!filtered.contains(name)) filtered.add(name);
        }

        if (filtered.isEmpty()) {
            header.remove("crit");
        } else {
            header.put("crit", filtered);
        }

        // Ensure RFC 7797: if b64=false, b64 must be in crit
        enforceCritForB64False();
        return this;
    }

    /** Compact JSON (single line). */
    public String toCompactJson() {
        return toJson(header, false, 0);
    }

    /** Pretty JSON (indented). */
    public String toPrettyJson() {
        return toJson(header, true, 0);
    }

    /** Base64URL(compact JSON) without padding. */
    public String toBase64Url() {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(toCompactJson().getBytes(StandardCharsets.UTF_8));
    }

    /* ========================= Internal ========================= */

    /** sigT normalization: "CURRENT" -> current UTC time (seconds, 'Z'). */
    private static Object normalizeSigT(Object v) {
        if (v instanceof String s && s.equalsIgnoreCase("CURRENT")) {
            return Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        }
        return deepCopy(v);
    }

    /** Add names to "crit" (additive, no duplicates). */
    private void addCritical(String... names) {
        List<String> crit = currentCritList();
        for (String n : names) {
            if (n == null) continue;
            if (!crit.contains(n)) crit.add(n);
        }
        header.put("crit", crit);
    }

    /** Merge an incoming crit value (String/Array/List) additively. */
    private void mergeCrit(Object v) {
        List<String> crit = currentCritList();
        forEachStringish(v, s -> { if (!crit.contains(s)) crit.add(s); });
        header.put("crit", crit);
    }

    /** Current crit list (never null). */
    private List<String> currentCritList() {
        List<String> crit = new ArrayList<>();
        Object c = header.get("crit");
        if (c instanceof List<?> L) {
            for (Object it : L) if (it != null) {
                String s = String.valueOf(it);
                if (!crit.contains(s)) crit.add(s);
            }
        } else if (c instanceof String s) {
            if (!s.isEmpty()) crit.add(s);
        } else if (c != null && c.getClass().isArray()) {
            Object[] arr = asObjectArray(c);
            for (Object it : arr) if (it != null) {
                String s = String.valueOf(it);
                if (!crit.contains(s)) crit.add(s);
            }
        }
        return crit;
    }

    /** Enforce "b64" in crit if b64=false is set (RFC 7797). */
    private void enforceCritForB64False() {
        Object b64 = header.get("b64");
        if (Boolean.FALSE.equals(b64)) {
            addCritical("b64");
        }
    }

    /* ========================= JSON (Ser/Deser) ========================= */

    private static String toJson(Object value, boolean pretty, int indent) {
        if (value == null) return "null";
        if (value instanceof String s) return "\"" + jsonEscape(s) + "\"";
        if (value instanceof Boolean b) return String.valueOf(b);

        // IMPORTANT: stable number rendering (no trailing ".0", no scientific notation)
        if (value instanceof Number n) {
            return numberToJson(n);
        }

        if (value instanceof Map<?, ?> map) {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (!first) sb.append(",");
                if (pretty) sb.append("\n").append(" ".repeat(indent + 2));
                first = false;
                sb.append("\"").append(jsonEscape(String.valueOf(e.getKey()))).append("\":");
                if (pretty) sb.append(" ");
                sb.append(toJson(e.getValue(), pretty, indent + 2));
            }
            if (pretty && !map.isEmpty()) sb.append("\n").append(" ".repeat(indent));
            sb.append("}");
            return sb.toString();
        }

        if (value instanceof List<?> list) {
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(",");
                if (pretty) sb.append("\n").append(" ".repeat(indent + 2));
                sb.append(toJson(list.get(i), pretty, indent + 2));
            }
            if (pretty && !list.isEmpty()) sb.append("\n").append(" ".repeat(indent));
            sb.append("]");
            return sb.toString();
        }

        if (value.getClass().isArray()) {
            Object[] arr = asObjectArray(value);
            return toJson(Arrays.asList(arr), pretty, indent);
        }

        return "\"" + jsonEscape(String.valueOf(value)) + "\"";
    }

    /**
     * Convert Number to JSON number string:
     * - BigDecimal is rendered as plain string (no exponent)
     * - trailing zeros removed (1712.0 -> 1712)
     * - "-0" normalized to "0"
     */
    private static String numberToJson(Number n) {
        BigDecimal bd;
        if (n instanceof BigDecimal b) {
            bd = b;
        } else {
            // Avoid Double/Float binary artifacts by using toString()
            bd = new BigDecimal(n.toString());
        }

        bd = bd.stripTrailingZeros();
        String s = bd.toPlainString();

        // normalize "-0" -> "0"
        if (s.startsWith("-0") && (s.length() == 2 || (s.length() > 2 && s.charAt(2) == '.'))) {
            s = s.substring(1);
        }
        return s;
    }

    private static String jsonEscape(String s) {
        return s.replace("\\","\\\\").replace("\"","\\\"")
                .replace("\r","\\r").replace("\n","\\n").replace("\t","\\t");
    }

    private static Object parseJson(String s) {
        return new MiniJson(s).parse();
    }

    private static class MiniJson {
        private final String s; private int i=0;
        MiniJson(String s){ this.s=s; }

        Object parse(){
            skipWs();
            Object v=parseValue();
            skipWs();
            if(i!=s.length()) throw new IllegalArgumentException("Extra chars");
            return v;
        }

        private Object parseValue(){
            skipWs();
            if(i>=s.length()) throw new IllegalArgumentException("Unexpected end");
            char c=s.charAt(i);
            return switch(c){
                case '{'->parseObject();
                case '['->parseArray();
                case '"'->parseString();
                case 't'->parseLiteral("true", Boolean.TRUE);
                case 'f'->parseLiteral("false", Boolean.FALSE);
                case 'n'->parseLiteral("null", null);
                default->parseNumber();
            };
        }

        private Map<String,Object> parseObject(){
            expect('{'); skipWs();
            LinkedHashMap<String,Object> m=new LinkedHashMap<>();
            if(peek('}')){ expect('}'); return m; }
            while(true){
                String k=parseString(); skipWs(); expect(':'); skipWs();
                Object v=parseValue(); m.put(k,v); skipWs();
                if(peek('}')){ expect('}'); break; }
                expect(','); skipWs();
            }
            return m;
        }

        private List<Object> parseArray(){
            expect('['); skipWs();
            List<Object> L=new ArrayList<>();
            if(peek(']')){ expect(']'); return L; }
            while(true){
                L.add(parseValue()); skipWs();
                if(peek(']')){ expect(']'); break; }
                expect(','); skipWs();
            }
            return L;
        }

        private String parseString(){
            expect('"'); StringBuilder sb=new StringBuilder();
            while(i<s.length()){
                char c=s.charAt(i++);
                if(c=='"') return sb.toString();
                if(c=='\\'){
                    char e=s.charAt(i++);
                    switch(e){
                        case '"','\\','/'->sb.append(e);
                        case 'b'->sb.append('\b');
                        case 'f'->sb.append('\f');
                        case 'n'->sb.append('\n');
                        case 'r'->sb.append('\r');
                        case 't'->sb.append('\t');
                        case 'u'->{
                            String hex=s.substring(i,i+4); i+=4;
                            sb.append((char)Integer.parseInt(hex,16));
                        }
                        default->throw new IllegalArgumentException("Bad escape: "+e);
                    }
                } else sb.append(c);
            }
            throw new IllegalArgumentException("Unterminated string");
        }

        private Object parseLiteral(String name, Object val){
            for(int j=0;j<name.length();j++) expect(name.charAt(j));
            return val;
        }

        /**
         * Parse JSON number as BigDecimal (lossless for typical header use-cases).
         * Supports optional fraction and exponent (e/E).
         */
        private Number parseNumber(){
            int start = i;

            if (s.charAt(i) == '-') i++;

            boolean hasIntDigits = false;
            while (i < s.length() && Character.isDigit(s.charAt(i))) {
                i++;
                hasIntDigits = true;
            }

            if (i < s.length() && s.charAt(i) == '.') {
                i++;
                boolean hasFracDigits = false;
                while (i < s.length() && Character.isDigit(s.charAt(i))) {
                    i++;
                    hasFracDigits = true;
                }
                if (!hasFracDigits) throw new IllegalArgumentException("Invalid number fraction");
            }

            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                boolean hasExpDigits = false;
                while (i < s.length() && Character.isDigit(s.charAt(i))) {
                    i++;
                    hasExpDigits = true;
                }
                if (!hasExpDigits) throw new IllegalArgumentException("Invalid number exponent");
            }

            if (!hasIntDigits) throw new IllegalArgumentException("Invalid number");

            String num = s.substring(start, i);
            try {
                return new BigDecimal(num);
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("Bad number: " + num, ex);
            }
        }

        private void skipWs(){ while(i<s.length() && Character.isWhitespace(s.charAt(i))) i++; }
        private void expect(char c){ if(i>=s.length()||s.charAt(i)!=c) throw new IllegalArgumentException("Expected "+c); i++; }
        private boolean peek(char c){ return i<s.length() && s.charAt(i)==c; }
    }

    /* ========================= Utilities ========================= */

    private static Object deepCopy(Object v) {
        if (v == null || v instanceof String || v instanceof Number || v instanceof Boolean) return v;

        if (v instanceof List<?> L) {
            List<Object> out = new ArrayList<>(L.size());
            for (Object o : L) out.add(deepCopy(o));
            return out;
        }

        if (v instanceof Map<?, ?> M) {
            LinkedHashMap<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : M.entrySet()) {
                out.put(String.valueOf(e.getKey()), deepCopy(e.getValue()));
            }
            return out;
        }

        if (v.getClass().isArray()) return Arrays.asList(asObjectArray(v));
        return String.valueOf(v);
    }

    private static Object[] asObjectArray(Object array) {
        if (array instanceof Object[]) return (Object[]) array;
        int len = java.lang.reflect.Array.getLength(array);
        Object[] out = new Object[len];
        for (int j = 0; j < len; j++) out[j] = java.lang.reflect.Array.get(array, j);
        return out;
    }

    /** Utility: iterate values as strings (String / Array / List). */
    private static void forEachStringish(Object v, java.util.function.Consumer<String> c) {
        if (v == null) return;
        if (v instanceof List<?> L) {
            for (Object it : L) if (it != null) c.accept(String.valueOf(it));
        } else if (v.getClass().isArray()) {
            Object[] arr = asObjectArray(v);
            for (Object it : arr) if (it != null) c.accept(String.valueOf(it));
        } else {
            c.accept(String.valueOf(v));
        }
    }
}