package artificialrobotics.com.SigningAuthorisation.JSON;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

import artificialrobotics.com.SigningAuthorisation.jose.ProtectedHeader;

public class ProtectedHeaderSmokeTest {

    public static void main(String[] args) throws Exception {
        int failed = 0;

        failed += testInitAndDeepCopy();
        failed += testSigTCurrentAddsCrit();
        failed += testSubAddsCrit();
        failed += testB64FalseAddsCrit();
        failed += testCritMergingNoDuplicates();
        failed += testApplyOverridesJson();
        failed += testJsonOutputsAndBase64();
        failed += testAsObjectMapIsDeepCopy();
        failed += testAsStringMapFormatting();
        failed += testJsonEscaping();

        System.out.println("\n================================");
        System.out.println("ProtectedHeader smoke tests - failed: " + failed);
        System.out.println("================================");
        if (failed > 0) System.exit(1);
    }

    /* ========================= Einzeltests ========================= */

    static int testInitAndDeepCopy() {
        try {
        	List<String> critList = new ArrayList<String>();
        	critList.add("sigT");
            Map<String, Object> base = new LinkedHashMap<>();
            base.put("alg", "PS512");
            base.put("x5u", "https://example.org/cert.pem");
            base.put("crit", critList); // vorinitialisiert

            ProtectedHeader ph = new ProtectedHeader(base);
            // Mutate base afterwards → ph must not change (deep copy)
            ((List<String>) base.get("crit")).add("sub");
            base.put("newField", "SHOULD_NOT_APPEAR");

            Map<String, Object> m = ph.asObjectMap();
            assertTrue("init: alg present", "PS512".equals(m.get("alg")));
            assertTrue("init: x5u present", "https://example.org/cert.pem".equals(m.get("x5u")));
            List<?> crit = (List<?>) m.get("crit");
            assertTrue("init: crit contains sigT", crit != null && crit.contains("sigT"));
            assertTrue("init: deep copy unaffected", m.get("newField") == null);
            ok("Init & deep copy");
            return 0;
        } catch (Throwable t) {
            fail("Init & deep copy", t);
            return 1;
        }
    }

    static int testSigTCurrentAddsCrit() {
        try {
            ProtectedHeader ph = new ProtectedHeader();
            ph.put("sigT", "CURRENT");
            Map<String, Object> m = ph.asObjectMap();
            String sigT = (String) m.get("sigT");
            assertTrue("sigT current → ISO-UTC",
                    sigT != null && ISO_INSTANT_SECONDS.matcher(sigT).matches());
            List<?> crit = (List<?>) m.get("crit");
            assertTrue("crit contains sigT", crit != null && crit.contains("sigT"));
            ok("sigT=CURRENT → iso + crit");
            return 0;
        } catch (Throwable t) {
            fail("sigT=CURRENT → iso + crit", t);
            return 1;
        }
    }

    static int testSubAddsCrit() {
        try {
            ProtectedHeader ph = new ProtectedHeader();
            ph.put("sub", "myResource123");
            Map<String, Object> m = ph.asObjectMap();
            assertEquals("sub value", "myResource123", m.get("sub"));
            List<?> crit = (List<?>) m.get("crit");
            assertTrue("crit contains sub", crit != null && crit.contains("sub"));
            ok("sub → crit");
            return 0;
        } catch (Throwable t) {
            fail("sub → crit", t);
            return 1;
        }
    }

    static int testB64FalseAddsCrit() {
        try {
            ProtectedHeader ph = new ProtectedHeader();
            ph.put("b64", false); // enforceCritForB64False
            Map<String, Object> m = ph.asObjectMap();
            assertEquals("b64 set", Boolean.FALSE, m.get("b64"));
            List<?> crit = (List<?>) m.get("crit");
            assertTrue("crit contains b64", crit != null && crit.contains("b64"));
            ok("b64=false → crit contains b64");
            return 0;
        } catch (Throwable t) {
            fail("b64=false → crit contains b64", t);
            return 1;
        }
    }

    static int testCritMergingNoDuplicates() {
        try {
            ProtectedHeader ph = new ProtectedHeader();
            ph.put("crit", List.of("a", "b"));
            ph.put("crit", new String[]{"b", "c"});
            ph.put("crit", "a"); // duplicate
            Map<String, Object> m = ph.asObjectMap();
            List<String> crit = castListOfString(m.get("crit"));
            // order: starts with a,b then c appended; duplicates not added
            assertEquals("crit size", 3, crit.size());
            assertTrue("crit contains a", crit.contains("a"));
            assertTrue("crit contains b", crit.contains("b"));
            assertTrue("crit contains c", crit.contains("c"));
            ok("crit merge (dedupe)");
            return 0;
        } catch (Throwable t) {
            fail("crit merge (dedupe)", t);
            return 1;
        }
    }

    static int testApplyOverridesJson() {
        try {
            ProtectedHeader ph = new ProtectedHeader(Map.of(
                    "alg", "PS512",
                    "crit", List.of("b64")
            ));
            String overrides = """
            {
              "sigT": "CURRENT",
              "sub": "abc-123",
              "crit": ["sigT","x-extra"],
              "x5u": "https://ex.org/cert.pem"
            }
            """;
            ph.applyOverridesJson(overrides);

            Map<String, Object> m = ph.asObjectMap();
            assertEquals("alg unchanged", "PS512", m.get("alg"));
            assertEquals("sub set", "abc-123", m.get("sub"));
            assertEquals("x5u set", "https://ex.org/cert.pem", m.get("x5u"));

            String sigT = (String) m.get("sigT");
            assertTrue("sigT resolved", sigT != null && ISO_INSTANT_SECONDS.matcher(sigT).matches());

            List<String> crit = castListOfString(m.get("crit"));
            // should contain b64 (from base), sigT (auto), sub (auto), and x-extra (from overrides)
            assertTrue("crit contains b64", crit.contains("b64"));
            assertTrue("crit contains sigT", crit.contains("sigT"));
            assertTrue("crit contains sub", crit.contains("sub"));
            assertTrue("crit contains x-extra", crit.contains("x-extra"));

            // NOT automatically adding other fields (like canonAlg) – matches current implementation.

            ok("applyOverridesJson");
            return 0;
        } catch (Throwable t) {
            fail("applyOverridesJson", t);
            return 1;
        }
    }

    static int testJsonOutputsAndBase64() {
        try {
            ProtectedHeader ph = new ProtectedHeader(Map.of(
                    "alg", "PS512",
                    "sub", "RID-1"
            ));
            ph.put("sigT", "CURRENT");
            String compact = ph.toCompactJson();
            String pretty  = ph.toPrettyJson();
            String b64     = ph.toBase64Url();

            assertTrue("compact non-empty", compact != null && !compact.isBlank());
            assertTrue("pretty contains newlines/indent", pretty.contains("\n"));
            // decode to verify base64url relationship
            String decoded = new String(Base64.getUrlDecoder().decode(b64), StandardCharsets.UTF_8);
            assertEquals("b64 is Base64URL(compact)", compact, decoded);

            ok("toCompact/toPretty/toBase64Url");
            return 0;
        } catch (Throwable t) {
            fail("toCompact/toPretty/toBase64Url", t);
            return 1;
        }
    }

    static int testAsObjectMapIsDeepCopy() {
        try {
            ProtectedHeader ph = new ProtectedHeader();
            ph.put("crit", new ArrayList<>(List.of("a")));
            Map<String, Object> m = ph.asObjectMap();
            @SuppressWarnings("unchecked")
            List<String> crit = (List<String>) m.get("crit");
            crit.add("MUTATE_OUTSIDE"); // mutate the returned copy
            // original must not change
            List<String> original = castListOfString(ph.asObjectMap().get("crit"));
            assertTrue("original not mutated", !original.contains("MUTATE_OUTSIDE"));
            ok("asObjectMap deep copy");
            return 0;
        } catch (Throwable t) {
            fail("asObjectMap deep copy", t);
            return 1;
        }
    }

    static int testAsStringMapFormatting() {
        try {
            ProtectedHeader ph = new ProtectedHeader();
            ph.put("sigT", "CURRENT");
            ph.put("sub", "X");
            Map<String, String> sm = ph.asStringMap();
            assertTrue("asStringMap has sigT", sm.containsKey("sigT"));
            assertTrue("asStringMap has sub", sm.containsKey("sub"));
            assertTrue("asStringMap value non-null", sm.get("sigT") != null);
            ok("asStringMap");
            return 0;
        } catch (Throwable t) {
            fail("asStringMap", t);
            return 1;
        }
    }

    static int testJsonEscaping() {
        try {
            ProtectedHeader ph = new ProtectedHeader();
            ph.put("x", "a\"b\\c\r\n\t");
            String compact = ph.toCompactJson();
            // simple contains checks
            assertTrue("escape quote", compact.contains("\\\""));
            assertTrue("escape backslash", compact.contains("\\\\"));
            assertTrue("escape CR", compact.contains("\\r"));
            assertTrue("escape LF", compact.contains("\\n"));
            assertTrue("escape TAB", compact.contains("\\t"));
            ok("JSON escaping");
            return 0;
        } catch (Throwable t) {
            fail("JSON escaping", t);
            return 1;
        }
    }

    /* ========================= Helpers ========================= */

    private static final Pattern ISO_INSTANT_SECONDS =
            Pattern.compile("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$");

    static void assertTrue(String msg, boolean cond) {
        if (!cond) throw new AssertionError("AssertTrue failed: " + msg);
    }
    static void assertEquals(String msg, Object exp, Object act) {
        if (!Objects.equals(exp, act))
            throw new AssertionError("AssertEquals failed: " + msg + " (exp=" + exp + ", act=" + act + ")");
    }
    static List<String> castListOfString(Object v) {
        if (v == null) return List.of();
        if (v instanceof List<?> L) {
            ArrayList<String> out = new ArrayList<>(L.size());
            for (Object o : L) out.add(String.valueOf(o));
            return out;
        }
        throw new IllegalArgumentException("Not a List: " + v);
    }
    static void ok(String name) { System.out.println("[OK]   " + name); }
    static void fail(String name, Throwable t) {
        System.err.println("[FAIL] " + name + " -> " + t.getMessage());
        t.printStackTrace(System.err);
    }
}
