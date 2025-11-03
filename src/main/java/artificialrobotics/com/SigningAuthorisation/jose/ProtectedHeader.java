package artificialrobotics.com.SigningAuthorisation.jose;

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

    /* ========================= Externe API ========================= */

    /** Vollständige Kopie als Map<String,Object>. */
    public Map<String, Object> asObjectMap() {
        LinkedHashMap<String, Object> copy = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : header.entrySet()) {
            copy.put(e.getKey(), deepCopy(e.getValue()));
        }
        return copy;
    }

    /** String-Darstellung aller Werte. */
    public Map<String, String> asStringMap() {
        LinkedHashMap<String, String> map = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : header.entrySet()) {
            map.put(e.getKey(), (e.getValue() == null) ? "null" : String.valueOf(e.getValue()));
        }
        return map;
    }

    /**
     * Setzt/überschreibt ein Feld.
     * - "sigT": Wert "CURRENT" (case-insensitive) wird zur aktuellen UTC-Zeit (ISO 8601, Sekunde, 'Z').
     * - "crit": wird additiv gemerged (Duplikate entfernt).
     * - "sigT" oder "sub": werden automatisch in "crit" aufgenommen (JWS-konform).
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
            case "crit" -> {
                mergeCrit(value);
            }
            default -> {
                header.put(key, deepCopy(value));
            }
        }

        enforceCritForB64False();
        return this;
    }

    /**
     * Wendet Overrides aus JSON an.
     * - "crit" wird additiv gemerged.
     * - "sigT" = "CURRENT" → aktuelle UTC-Zeit.
     * - Bei "sigT" und "sub" wird "crit" automatisch ergänzt.
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

    /** Kompaktes JSON (eine Zeile). */
    public String toCompactJson() {
        return toJson(header, false, 0);
    }

    /** Formatiertes JSON (eingerückt). */
    public String toPrettyJson() {
        return toJson(header, true, 0);
    }

    /** Base64URL(kompaktes JSON) ohne Padding. */
    public String toBase64Url() {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(toCompactJson().getBytes(StandardCharsets.UTF_8));
    }

    /* ========================= Internes ========================= */

    /** sigT-Normalisierung: "CURRENT" -> aktuelle UTC-Zeit (bis Sekunde, 'Z'). */
    private static Object normalizeSigT(Object v) {
        if (v instanceof String s && s.equalsIgnoreCase("CURRENT")) {
            // ISO-8601, Sekundenauflösung, Z-Suffix
            return Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        }
        return deepCopy(v);
    }

    /** Fügt Namen zu crit hinzu (additiv, ohne Duplikate). */
    private void addCritical(String... names) {
        List<String> crit = currentCritList();
        for (String n : names) {
            if (n == null) continue;
            if (!crit.contains(n)) crit.add(n);
        }
        header.put("crit", crit);
    }

    /** Merged eingehenden crit-Wert (String/Array/List) additiv. */
    private void mergeCrit(Object v) {
        List<String> crit = currentCritList();
        forEachStringish(v, s -> { if (!crit.contains(s)) crit.add(s); });
        header.put("crit", crit);
    }

    /** Liefert aktuelle crit-Liste (nie null). */
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

    /** Erzwingt "b64" in crit, falls b64=false gesetzt ist. */
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
        if (value instanceof Number || value instanceof Boolean) return String.valueOf(value);
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
        Object parse(){ skipWs(); Object v=parseValue(); skipWs(); if(i!=s.length()) throw new IllegalArgumentException("Extra chars"); return v; }
        private Object parseValue(){
            skipWs(); if(i>=s.length()) throw new IllegalArgumentException("Unexpected end");
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
        private Object parseLiteral(String name, Object val){ for(int j=0;j<name.length();j++) expect(name.charAt(j)); return val; }
        private Number parseNumber(){
            int start=i; if(s.charAt(i)=='-') i++;
            while(i<s.length() && Character.isDigit(s.charAt(i))) i++;
            if(i<s.length() && s.charAt(i)=='.'){ i++; while(i<s.length()&&Character.isDigit(s.charAt(i))) i++; }
            String num=s.substring(start,i);
            return num.contains(".") ? Double.parseDouble(num) : Long.parseLong(num);
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
        for (int i = 0; i < len; i++) out[i] = java.lang.reflect.Array.get(array, i);
        return out;
    }

    /** Utility: iteriert Werte als Strings (String / Array / List). */
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
