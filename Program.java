import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;

public class Program {
	public static void main(String[] args) {
		
		if (args.length != 3) {
			displayHelp();
			return;
		} else {
			
			try {
				String command = args[0];
				String inputFile = args[1];
				String outputFile = args[2];			
				String password = getPassword();			
							
				AesCryptography crypto = new AesCryptography();
				
				Key key = crypto.getKey(password);
				
				byte[] inputContent = getContent(inputFile);
				byte[] outputContent = null;
				
				byte[] bKey = key.getEncoded();
				for(int i = 0; i < bKey.length; ++i) {
					System.out.println(bKey[i]);
				}
				System.out.println(key.getEncoded().length);
				switch (command) {
				case "encrypt":		
					outputContent = crypto.encryptWithAes(inputContent, key);
					break;
				case "decrypt":
					outputContent = crypto.decryptWithAes(inputContent, key);
					break;
				default:
					displayHelp();
					break;
				}
						
				saveContent(outputContent, outputFile);
			} 
			catch(Exception ex) {
				ex.printStackTrace();
			}
		}
	}
	
	private static String getPassword() {
		return "1234";
	}
	
	private static byte[] getContent(String fileName) throws IOException {
		Path path = Paths.get(fileName);
		return Files.readAllBytes(path);
	}
	
	private static void saveContent(byte[] content, String fileName) throws IOException {
		Path path = Paths.get(fileName);
		Files.write(path, content);
	}
	
	public static void displayHelp() {
		System.out.println("AesCryptography");
		System.out.println("===============");
		System.out.println();
		System.out.println("Usage:");
		System.out.println("AesCryptography encrypt [input file] [output file]");
		System.out.println("AesCryptography decrypt [input file] [output file]");
		System.out.println();    
	}
}
