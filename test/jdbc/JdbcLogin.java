import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Logs in through a JDBC URL, once for each password it reads.
 *
 * <p>For tests/test_password_paths.py. Everything comes on stdin, none of it in
 * argv (invariant 1). The first line is the account, the second is the address,
 * {@code //host:port/service}. Each line after that is a password as it goes in
 * the URL, with or without double quotes. For each one it connects to
 * {@code jdbc:oracle:thin:account/password@address} and prints one line:
 * {@code LOGGEDIN}, or {@code FAILED} and the reason.
 *
 * <p>It prints {@code READY} once it has read the address, so the caller knows
 * the JVM is up before it starts the clock on a login.
 */
public class JdbcLogin {
    public static void main(String[] args) throws Exception {
        BufferedReader in =
                new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        String account = in.readLine();
        String address = in.readLine();
        out.println("READY");
        String password;
        while ((password = in.readLine()) != null) {
            out.println(login("jdbc:oracle:thin:" + account + "/" + password + "@" + address));
        }
    }

    private static String login(String url) {
        try (Connection connection = DriverManager.getConnection(url);
                Statement statement = connection.createStatement();
                ResultSet result = statement.executeQuery("select 'LOGGED' || 'IN' from dual")) {
            result.next();
            return result.getString(1);
        } catch (SQLException e) {
            return String.format("FAILED ORA-%05d %s", e.getErrorCode(), firstLine(e.getMessage()));
        } catch (RuntimeException e) {
            return "FAILED " + e.getClass().getName() + " " + firstLine(e.getMessage());
        }
    }

    private static String firstLine(String message) {
        return message == null ? "" : message.lines().findFirst().orElse("");
    }
}
