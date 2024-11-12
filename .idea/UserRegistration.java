import com.ba.beans.User;
import com.ba.db.DBConnection;
import com.ba.service.PasswordManagement;
import com.ba.service.SsnManager;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.sql.PreparedStatement;

public class UserRegistration {

    /**
     * Reads the User input credentials and creates a new
     * table entry if the user-supplied input is valid and
     * the supplied password is strong enough.
     * @param registerBean temporary communication object that
     * holds the user input credentials
     * @return String for success or SQLState Error
     */

    public String registerUser(User registerBean){
        String firstName = registerBean.getFirstName();
        String lastName = registerBean.getLastName();
        String email = registerBean.getEmail();
        String userName = registerBean.getUserName();
        String password = registerBean.getPassword();
        String salt = registerBean.getSalt();

        Connection con;
        PreparedStatement statement = null;

        PasswordManagement passwordManager = new PasswordManagement();

        if(!passwordManager.checkPasswordStrength(password)){
            return "Please use a stronger Password";
        }

        try {
            con = DBConnection.createConnection();
            statement = con.prepareStatement("insert into user values(?,?,?,?,?,?)");

            statement.setString(1, firstName);
            statement.setString(2, lastName);
            statement.setString(3, email);
            statement.setString(4, userName);
            statement.setString(5, generateHash(password));
            statement.setString(6, salt);

            int result = statement.executeUpdate();

            if(result!=0) {
                return "SUCCESS";
            }
        } catch (SQLException e) {
            String logMessage = "Unable to retrieve account information from database," +
                    "\\n query: " + statement;
            Logger.getLogger(SsnManager.class.getName()).log(Level.SEVERE, logMessage, e);
            return e.getSQLState();
        }

        return "Something went wrong";
    }
}

