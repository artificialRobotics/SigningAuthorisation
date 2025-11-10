package artificialrobotics.com.SigningAuthorisation.JSON;

import java.util.Objects;

import artificialrobotics.com.SigningAuthorisation.json.JsonCanonicalizerJcs;

public class JsonCanonicalizationSmokeTest {

    public static void main(String[] args) {
        int failed = 0;

        // Zahlen
        failed += ok("0", "0");
        failed += ok("-0", "0");
        failed += mustFail("01");     // führende Null muss scheitern
        failed += ok("1.0", "1");
        failed += ok("1.2300", "1.23");
        failed += ok("1e0", "1");
        failed += ok("1e-0", "1");
        failed += ok("-1e+10", "-10000000000");
        failed += ok("1000000000000000000000", "1000000000000000000000");

        // Strings / Escapes
        failed += ok("{\"a\":\"\\u0000\\u0001\\n\\r\\t\"}", "{\"a\":\"\\u0000\\u0001\\u000a\\u000d\\u0009\"}");
        failed += ok("{\"q\":\"\\\"\\\\\"}", "{\"q\":\"\\\"\\\\\"}");
        failed += ok("{\"e\":\"😊\"}", "{\"e\":\"😊\"}");

        // Key-Sortierung
        failed += ok("{\"b\":1,\"a\":2}", "{\"a\":2,\"b\":1}");
        failed += ok("{\"ä\":1,\"z\":2}", "{\"z\":2,\"ä\":1}");
        failed += ok("{\"b\":1,\"a\":{\"d\":4,\"c\":3}}", "{\"a\":{\"c\":3,\"d\":4},\"b\":1}");

        // Arrays
        failed += ok("[1,  2 , 3]", "[1,2,3]");
        failed += ok("[\"b\",\"a\"]", "[\"b\",\"a\"]");

        // Doppel-Keys (deterministisch; letzter gewinnt, danach Sortierung)
        failed += ok("{\"a\":1,\"a\":2}", "{\"a\":2}");

        // Nicht erlaubte Literale
        failed += mustFail("{\"x\": NaN}");
        failed += mustFail("{\"x\": Infinity}");

        System.out.println("\n================================");
        System.out.println("Failed cases: " + failed);
        System.out.println("================================");
        if (failed > 0) System.exit(1);
    }

    static int ok(String in, String expected) {
        try {
            String got = JsonCanonicalizerJcs.canonicalize(in);
            if (!Objects.equals(got, expected)) {
                System.err.println("[FAIL] in : " + in);
                System.err.println("       exp: " + expected);
                System.err.println("       got: " + got);
                return 1;
            }
            System.out.println("[OK]   " + in + "  ->  " + got);
            return 0;
        } catch (Throwable t) {
            System.err.println("[FAIL] " + in + " threw " + t);
            return 1;
        }
    }

    static int mustFail(String in) {
        try {
            String got = JsonCanonicalizerJcs.canonicalize(in);
            System.err.println("[FAIL] expected failure, but got: " + got + "  for input " + in);
            return 1;
        } catch (Throwable t) {
            System.out.println("[OK]   failed as expected: " + in + "  ->  " + t.getMessage());
            return 0;
        }
    }
}
