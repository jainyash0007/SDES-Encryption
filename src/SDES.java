import java.util.Arrays;
public class SDES {
	public static void main(String[] args){
		System.out.println("------------------------------------------------");
		System.out.println("              Part 1 SDES Table");
		System.out.println("------------------------------------------------");
		System.out.println("  Raw Key   |   Plain Text   |  Cipher Text   ");
		System.out.println("------------------------------------------------");
		encryptFunction();
		decryptFunction();
		System.out.println("------------------------------------------------");
	}

	private static void encryptFunction(){
		byte[][] key = new byte[4][];
		byte[][] plaintxt = new byte[4][];
		byte[][] ciphertxt = new byte[4][];

		key[0] = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		key[1] = new byte[]{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
		key[2] = new byte[]{ 0, 0, 0, 0, 0, 1, 1, 1, 1, 1 };
		key[3] = new byte[]{ 0, 0, 0, 0, 0, 1, 1, 1, 1, 1 };

		plaintxt[0] = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 };
		plaintxt[1] = new byte[]{ 1, 1, 1, 1, 1, 1, 1, 1 };
		plaintxt[2] = new byte[]{ 0, 0, 0, 0, 0, 0, 0, 0 };
		plaintxt[3] = new byte[]{ 1, 1, 1, 1, 1, 1, 1, 1 };

		for(int i = 0; i < 4; i++){
			ciphertxt[i] = SDES.Encrypt(key[i], plaintxt[i]);
			printArray(key[i]);
			System.out.print("  |   ");
			printArray(plaintxt[i]);
			System.out.print("     |   ");
			printArray(ciphertxt[i]);
			System.out.println();
		}
	}

	private static void decryptFunction(){
		byte[][] key = new byte[4][];
		byte[][] plaintxt = new byte[4][];
		byte[][] ciphertxt = new byte[4][];

		key[0] = new byte[]{ 1, 0, 0, 0, 1, 0, 1, 1, 1, 0 };
		key[1] = new byte[]{ 1, 0, 0, 0, 1, 0, 1, 1, 1, 0 };
		key[2] = new byte[]{ 0, 0, 1, 0, 0, 1, 1, 1, 1, 1 };
		key[3] = new byte[]{ 0, 0, 1, 0, 0, 1, 1, 1, 1, 1 };

		ciphertxt[0] = new byte[]{ 0, 0, 0, 1, 1, 1, 0, 0 };
		ciphertxt[1] = new byte[]{ 1, 1, 0, 0, 0, 0, 1, 0 };
		ciphertxt[2] = new byte[]{ 1, 0, 0, 1, 1, 1, 0, 1 };
		ciphertxt[3] = new byte[]{ 1, 0, 0, 1, 0, 0, 0, 0 };

		for(int i = 0; i < 4; i++){
			plaintxt[i] = SDES.Decrypt(key[i], ciphertxt[i]);
			printArray(key[i]);
			System.out.print("  |   ");
			printArray(plaintxt[i]);
			System.out.print("     |   ");
			printArray(ciphertxt[i]);
			System.out.println();
		}
	}

	public static void printArray(byte[] array){
		int iterate = 0;
		while(iterate < array.length){
			System.out.print(array[iterate]);
			iterate++;
		}
	}

	public static byte[] Encrypt(byte[] rawkey, byte[] plaintxt){
		byte[] key1 = new byte[8];
		byte[] key2 = new byte[8];
		generateKeys(rawkey, key1, key2);


		int size = (int) Math.ceil(plaintxt.length / 8) * 8;
		byte[] ciphertxt = new byte[size];

		int count = 0;
		while ( count < plaintxt.length){
			byte[] subplaintxt = Arrays.copyOfRange(plaintxt, count, count + 8);
			byte[] temp = encryptData(key1, key2, subplaintxt);
			int loop = 0;
			while(loop < 8){
				ciphertxt[loop + count] =  temp[loop];
				loop ++;
			}
			count += 8;	
		}
		return ciphertxt;
	}
	
	public static byte[] Decrypt(byte[] rawkey, byte[] ciphertxt){
		byte[] key1 = new byte[8];
		byte[] key2 = new byte[8];
		generateKeys(rawkey, key1, key2);


		int size = (int) Math.ceil(ciphertxt.length / 8) * 8;
		byte[] plaintxt = new byte[size];

		int txt = 0;
		while (txt < ciphertxt.length){
			byte[] subciphertxt = Arrays.copyOfRange(ciphertxt, txt, txt+8);
			byte[] temp = decryptData(key1, key2, subciphertxt);
			int innerLoop = 0;
			while(innerLoop < 8){
				plaintxt[innerLoop + txt] =  temp[innerLoop];
				innerLoop ++;
			}
			txt += 8;
		}
		return plaintxt;
	}


	public static byte[] encryptData(byte[] key1, byte[] key2, byte[] plaintxt){
		byte[] temp = initialPermute(plaintxt);
		fk(temp, key1);
		temp = switchHalves8(temp);
		fk(temp, key2);
		temp = finalPermute(temp);
		return temp;
	}
	
	public static byte[] decryptData(byte[] key1, byte[] key2, byte[] ciphertxt){
		byte[] temp = initialPermute(ciphertxt);
		fk(temp, key2);
		temp = switchHalves8(temp);
		fk(temp, key1);
		temp = finalPermute(temp);
		return temp;
	}
	

	private static void generateKeys(byte[] rawkey, byte[] k1, byte[] k2){
		byte[] afterP10 = keyGenPermute10(rawkey);
		byte[] afterS1 = keyGenShift(afterP10, 1);
		keyGenPermute10to8(afterS1, k1);
		byte[] afterS2 = keyGenShift(afterS1, 2);
		keyGenPermute10to8(afterS2, k2);
	}
	
	private static byte[] keyGenPermute10(byte[] bitInput){
		
		byte[] bitOutput = new byte[10];
		bitOutput[0] = bitInput[2];
		bitOutput[1] = bitInput[4];
		bitOutput[2] = bitInput[1];
		bitOutput[3] = bitInput[6];
		bitOutput[4] = bitInput[3];
		bitOutput[5] = bitInput[9];
		bitOutput[6] = bitInput[0];
		bitOutput[7] = bitInput[8];
		bitOutput[8] = bitInput[7];
		bitOutput[9] = bitInput[5];
		
		return bitOutput;
	}
	
	private static byte[] keyGenShift(byte[] bitInput, int shiftAmount){
		
		byte[] bitOutput = new byte[10];
		bitOutput[0] = bitInput[(0 + shiftAmount) % 5];
		bitOutput[1] = bitInput[(1 + shiftAmount) % 5];
		bitOutput[2] = bitInput[(2 + shiftAmount) % 5];
		bitOutput[3] = bitInput[(3 + shiftAmount) % 5];
		bitOutput[4] = bitInput[(4 + shiftAmount) % 5];
		bitOutput[5] = bitInput[(0 + shiftAmount) % 5 + 5];
		bitOutput[6] = bitInput[(1 + shiftAmount) % 5 + 5];
		bitOutput[7] = bitInput[(2 + shiftAmount) % 5 + 5];
		bitOutput[8] = bitInput[(3 + shiftAmount) % 5 + 5];
		bitOutput[9] = bitInput[(4 + shiftAmount) % 5 + 5];
		
		return bitOutput;
	}
	
	private static void keyGenPermute10to8(byte[] bitInput, byte[] bitOutput){
		if(bitInput == null){
			System.out.println("Error: SDES.keyGenPermutation10to8(bitInput, bitOutput) got null for bitInput");
			System.exit(1);
		}
		if(bitOutput == null){
			System.out.println("Error: SDES.keyGenPermutation10to8(bitInput, bitOutput) got null for bitOutput");
			System.exit(1);
		}
		if(bitInput.length != 10){
			System.out.println("Error: SDES.keyGenPermutation10to8(bitInput, bitOutput) got bitInput of incorrect size: " + bitInput.length + " instead of 10");
			System.exit(1);
		}		
		if(bitOutput.length != 8){
			System.out.println("Error: SDES.keyGenPermutation10to8(bitInput, bitOutput) got bitOutput of incorrect size: " + bitInput.length + " instead of 10");
			System.exit(1);
		}
		
		bitOutput[0] = bitInput[5];
		bitOutput[1] = bitInput[2];
		bitOutput[2] = bitInput[6];
		bitOutput[3] = bitInput[3];
		bitOutput[4] = bitInput[7];
		bitOutput[5] = bitInput[4];
		bitOutput[6] = bitInput[9];
		bitOutput[7] = bitInput[8];
	}
	
	
	private static byte[] initialPermute(byte[] bitInput){
		
		byte[] bitOutput = new byte[8];
		bitOutput[0] = bitInput[1];
		bitOutput[1] = bitInput[5];
		bitOutput[2] = bitInput[2];
		bitOutput[3] = bitInput[0];
		bitOutput[4] = bitInput[3];
		bitOutput[5] = bitInput[7];
		bitOutput[6] = bitInput[4];
		bitOutput[7] = bitInput[6];
		
		return bitOutput;
	}
	
	private static byte[] finalPermute(byte[] bitInput){
		
		byte[] bitOutput = new byte[8];
		bitOutput[0] = bitInput[3];
		bitOutput[1] = bitInput[0];
		bitOutput[2] = bitInput[2];
		bitOutput[3] = bitInput[4];
		bitOutput[4] = bitInput[6];
		bitOutput[5] = bitInput[1];
		bitOutput[6] = bitInput[7];
		bitOutput[7] = bitInput[5];
		
		return bitOutput;
	}
	
	
	private static byte[] switchHalves8(byte[] bitInput){
		
		byte[] bitOutput = new byte[8];
		bitOutput[0] = bitInput[4];
		bitOutput[1] = bitInput[5];
		bitOutput[2] = bitInput[6];
		bitOutput[3] = bitInput[7];
		bitOutput[4] = bitInput[0];
		bitOutput[5] = bitInput[1];
		bitOutput[6] = bitInput[2];
		bitOutput[7] = bitInput[3];
		
		return bitOutput;
	}
	
	
	private static void fk(byte[] bitInput, byte[] key){
		byte[] fromF = F(bitInput, key);
		int k = 0;
		while(k < 4){
			bitInput[k] = (byte)(bitInput[k] ^ fromF[k]);
			k++;
		}		
	}
	
	private static byte[] F(byte[] bitInput, byte[] key){
		
		byte[] temp = new byte[8];
		temp[0] = bitInput[7];
		temp[1] = bitInput[4];
		temp[2] = bitInput[5];
		temp[3] = bitInput[6];
		temp[4] = bitInput[5];
		temp[5] = bitInput[6];
		temp[6] = bitInput[7];
		temp[7] = bitInput[4];
		
		int  m = 0;
		while(m < 8){
			temp[m] = (byte)(temp[m] ^ key[m]);
			m++;
		}
		
		s0(temp);
		s1(temp);
		
		byte[] bitOutput = new byte[4];
		bitOutput[0] = temp[1];
		bitOutput[1] = temp[3];
		bitOutput[2] = temp[2];
		bitOutput[3] = temp[0];
		
		return bitOutput;
	}
	
	private static void s0(byte[] bitInput){
		byte row = (byte)(bitInput[0] * 2 + bitInput[3]);
		byte col = (byte)(bitInput[1] * 2 + bitInput[2]);
		
		byte value = s0Table[row][col];
		
		bitInput[0] = (byte)(value / 2);
		bitInput[1] = (byte)(value % 2);
	}
	
	private static void s1(byte[] bitInput){
		byte row = (byte)(bitInput[4] * 2 + bitInput[7]);
		byte col = (byte)(bitInput[5] * 2 + bitInput[6]);
		
		byte value = s1Table[row][col];
		
		bitInput[2] = (byte)(value / 2);
		bitInput[3] = (byte)(value % 2);
	}
	
	private static byte[][] s0Table = {
		{1, 0, 3, 2}, 
		{3, 2, 1, 0}, 
		{0, 2, 1, 3}, 
		{3, 1, 3, 2}
	};
	
	private static byte[][] s1Table = {
		{0, 1, 2, 3}, 
		{2, 0, 1, 3}, 
		{3, 0, 1, 0}, 
		{2, 1, 0, 3}
	};
}
