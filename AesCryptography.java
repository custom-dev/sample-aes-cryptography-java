import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AesCryptography {
	public static final String KEY_ALGORITHM = "AES";
	public static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";	
	
	/**
	 * Get the salt used to generate the key.
	 * No special consideration about security (salt can be public).
	 *         
	 * @return salt
	 */
	private byte[] getSalt() {
		return new byte[] {0, 1, 2, 3, 4, 5, 6, 7};
	}
	
	public Key getKey(String password) {
		byte[] salt = this.getSalt();
		
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 100, 256);
			SecretKey secretKey = factory.generateSecret(keySpec);
			Key key = new SecretKeySpec(secretKey.getEncoded(), KEY_ALGORITHM);
			return key;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;	
	}
	
	public byte[] encryptWithAes(byte[] plainContent, Key key) {
		if (plainContent == null || plainContent.length == 0) { throw new IllegalArgumentException("plainContent"); }
		if (key == null) { throw new IllegalArgumentException("key"); }
		
		try {
			SecureRandom random = new SecureRandom();
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			MessageDigest sha256 = MessageDigest.getInstance( "SHA-256" );

			byte[] initializationVector = new byte[16];
			random.nextBytes(initializationVector);
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);	        
	        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(initializationVector));	        

	        sha256.update(plainContent);
	        byte[] signature = sha256.digest();

	        buffer.write(initializationVector);
            
	        buffer.write(cipher.update(new byte[] {1}, 0, 1));
	        buffer.write(cipher.update(signature));
            buffer.write(cipher.doFinal(plainContent));
            
            //buffer.write(encryptedData);
            return buffer.toByteArray();
        } catch (Exception e) {
        	e.printStackTrace();            
        }
		
		return null;
	}
	
	public byte[] decryptWithAes(byte[] cipherContent, Key key) {
		if (cipherContent == null || cipherContent.length == 0) { throw new IllegalArgumentException("plainContent"); }
		if (key == null) { throw new IllegalArgumentException("key"); }
		
		try {
			byte[] initializationVector = new byte[16];
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			System.arraycopy(cipherContent, 0, initializationVector, 0, initializationVector.length);
			MessageDigest sha256 = MessageDigest.getInstance( "SHA-256" );

	        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(initializationVector));	        
	        	        
            byte[] decryptedData = cipher.doFinal(cipherContent, initializationVector.length, cipherContent.length - initializationVector.length);
            if (decryptedData[0] == 1)
            {
            	byte[] signature = new byte[32];
            	byte[] content = new byte[decryptedData.length - signature.length - 1] ;
            	
            	System.arraycopy(decryptedData,  signature.length + 1, content, 0, content.length);
            	System.arraycopy(decryptedData, 1, signature, 0, signature.length);
            	sha256.update(content);
            	
            	if (Arrays.equals(signature,  sha256.digest()))
            	{            		
            		return content;
            	}
            	else
            	{
            		throw new Exception("Corrupted data");
            	}
            }
            else
            {
            	throw new Exception("Corrupted data");
            }            
        } catch (Exception e) {
        	e.printStackTrace();            
        }
		
		return null;
	}
}
