package artificialrobotics.com.SigningAuthorisation.cli;

import picocli.CommandLine;

@CommandLine.Command(
    name = "sa",
    mixinStandardHelpOptions = true,
    version = "SigningAuthorisation 1.0",
    subcommands = {
        SignCmd.class,
        VerifyCmd.class,
        SignXmlCmd.class,
        VerifyXmlCmd.class
    }
)
public class App implements Runnable {

    public static void main(String[] args) {
        int exit = new CommandLine(new App()).execute(args);
        System.exit(exit);
    }

    @Override
    public void run() {
        System.out.println("Use subcommands: sign | verify | sign-xml | verify-xml");
    }
}