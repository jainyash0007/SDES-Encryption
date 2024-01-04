
public class TripleSDES {

	public static void main(String[] args){
		
		System.out.println("-----------------------------------------------------------------");
		System.out.println("                 Part 2 Triple SDES Table");
		System.out.println("-----------------------------------------------------------------");
		System.out.println("  Raw Key 1   |   Raw Key 2   |   Plain Text   |  Cipher Text   ");
		System.out.println("-----------------------------------------------------------------");
		codeForEncrypt();
		codeForDecrypt();
		System.out.println("-----------------------------------------------------------------");
	}
	
	private static void codeForEncrypt(){
		byte[][] key1 = new byte[4][];
		byte[][] key2 = new byte[4][];
		byte[][] txtPlain = new byte[4][];
		byte[][] txtCipher = new byte[4][];

		key1[0] = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		key1[1] = new byte[]{ 1, 0, 0, 0, 1, 0, 1, 1, 1, 0 };
		key1[2] = new byte[]{ 1, 0, 0, 0, 1, 0, 1, 1, 1, 0 };
		key1[3] = new byte[]{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };

		key2[0] = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		key2[1] = new byte[]{ 0, 1, 1, 0, 1, 0, 1, 1, 1, 0 };
		key2[2] = new byte[]{ 0, 1, 1, 0, 1, 0, 1, 1, 1, 0 };
		key2[3] = new byte[]{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };

		txtPlain[0] = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 };
		txtPlain[1] = new byte[]{ 1, 1, 0, 1, 0, 1, 1, 1 };
		txtPlain[2] = new byte[]{ 1, 0, 1, 0, 1, 0, 1, 0 };
		txtPlain[3] = new byte[]{ 1, 0, 1, 0, 1, 0, 1, 0 };

		int i = 0;
		while(i < 4){
			txtCipher[i] = TripleSDES.Encrypt(key1[i], key2[i], txtPlain[i]);
			printArray(key1[i]);
			System.out.print("    |   ");
			printArray(key2[i]);
			System.out.print("  |   ");
			printArray(txtPlain[i]);
			System.out.print("     |   ");
			printArray(txtCipher[i]);
			System.out.println();
			
			i++;
		}
	}


	private static void codeForDecrypt(){
		byte[][] key1 = new byte[4][];
		byte[][] key2 = new byte[4][];
		byte[][] txtPlain = new byte[4][];
		byte[][] txtCipher = new byte[4][];

		key1[0] = new byte[]{ 1, 0, 0, 0, 1, 0, 1, 1, 1, 0 };
		key1[1] = new byte[]{ 1, 0, 1, 1, 1, 0, 1, 1, 1, 1 };
		key1[2] = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		key1[3] = new byte[]{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };

		key2[0] = new byte[]{ 0, 1, 1, 0, 1, 0, 1, 1, 1, 0 };
		key2[1] = new byte[]{ 0, 1, 1, 0, 1, 0, 1, 1, 1, 0 };
		key2[2] = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		key2[3] = new byte[]{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };

		txtCipher[0] = new byte[]{ 1, 1, 1, 0, 0, 1, 1, 0 };
		txtCipher[1] = new byte[]{ 0, 1, 0, 1, 0, 0, 0, 0 };
		txtCipher[2] = new byte[]{ 1, 0, 0, 0, 0, 0, 0, 0 };
		txtCipher[3] = new byte[]{ 1, 0, 0, 1, 0, 0, 1, 0 };

		int i = 0;
		while(i < 4){
			txtPlain[i] = TripleSDES.Decrypt(key1[i], key2[i], txtCipher[i]);
			printArray(key1[i]);
			System.out.print("    |   ");
			printArray(key2[i]);
			System.out.print("  |   ");
			printArray(txtPlain[i]);
			System.out.print("     |   ");
			printArray(txtCipher[i]);
			System.out.println();

			i++;
		}
	}

	public static void printArray(byte[] array){
		int i = 0;
		while (i < array.length){
			System.out.print(array[i]);
			i++;
		}
	}

	public static byte[] Encrypt( byte[] rawkey1, byte[] rawkey2, byte[] txtPlain ){
		return SDES.Encrypt(rawkey1, SDES.Decrypt(rawkey2, SDES.Encrypt(rawkey1, txtPlain)));
	}
	public static byte[] Decrypt( byte[] rawkey1, byte[] rawkey2, byte[] txtCipher ){
		return SDES.Decrypt(rawkey1, SDES.Encrypt(rawkey2, SDES.Decrypt(rawkey1, txtCipher)));
	}
}
