package models;

/**
 * Created by Tobias on 24.04.2016.
 */

public class BTToken {

    private Token[] btTokens;

    BTToken() {

    }

    public static class Token {
        private String device;
        private String otp;
        private String publicKey;
        private byte[] IV;
        private byte[] salt;

        public Token() {

        }

        public String getDevice() {
            return device;
        }

        public void setDevice(String _device) {
            device = _device;
        }

        public String getOtp() {
            return otp;
        }

        public void setOtp(String _otp) {
            otp = _otp;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String _publicKey) {
            publicKey = _publicKey;
        }

        public byte[] getSalt() {
            return salt;
        }

        public void setSalt(byte[] _salt) {
            salt = _salt;
        }

        public byte[] getIV() {
            return IV;
        }

        public void setIV(byte[] IV) {
            this.IV = IV;
        }
    }

    public Token[] getBtTokens() {
        return btTokens;
    }

    public void setBtTokens(Token[] btTokens) {
        this.btTokens = btTokens;
    }
}
