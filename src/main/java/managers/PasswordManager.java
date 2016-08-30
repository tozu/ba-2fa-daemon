package managers;

import Utils.Encryption;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Created by Tobias on 7/6/2016.
 */
public class PasswordManager {

    private final String pwdFilePath = "./pwd.txt";
    private File pwdFile = new File(pwdFilePath);

    private Encryption encManager;

    private static PasswordManager mInstance;
    private String mPwdHash = null;

    public static PasswordManager getInstance() {
        if (mInstance == null) {
            mInstance = new PasswordManager();
        }
        return mInstance;
    }

    private PasswordManager() {
        loadFile();
        encManager = Encryption.getInstance();
    }

    private boolean loadFile() {
        if (!pwdFile.exists()) {
            try {
                return pwdFile.createNewFile();
            } catch (IOException e) {
                System.out.println("[ERROR] creating pwd file" + "\n" + e.getMessage());
            }
        } else {
            try {
                mPwdHash = FileUtils.readFileToString(pwdFile);
                return true;
            } catch (IOException e) {
                System.out.println("[ERROR] reading pwd file" + "\n" + e.getMessage());
            }
        }

        return false;
    }

    public boolean savePasswordToFile(String _pwd) {
        try {
            String pwdHash = encManager.createHASH_SHA256(_pwd);
            FileWriter fileWriter = new FileWriter(pwdFile);
            fileWriter.write(pwdHash);
            fileWriter.close();
            return true;
        } catch (IOException e) {
            System.out.println("[ERROR] writing pwd file" + "\n" + e.getMessage());
        }
        return false;
    }

    public String getPasswordHash() {
        return mPwdHash;
    }

}
