package hr.fer.kik;

import java.util.Objects;

import hr.fer.kik.specification.AESMethods;
import hr.fer.kik.util.AlgorithmUtils;
import hr.fer.kik.util.FiniteFieldsUtil;
import hr.fer.kik.util.IOUtils;
import hr.fer.kik.util.MatrixUtils;

/**
 * This class provides AES-128 functionality.
 * 
 * @author Ivan Lokas
 *
 */
public class AES128 implements Algorithm, AESMethods {
	/**
	 * Supported key length (AES-128)
	 */
	public final int KEY_LENGTH = 128;
	/**
	 * Supported data block length
	 */
	public final int DATA_BLOCK_LENGTH = 128;

	/**
	 * Number of columns (32-bit words) comprising the State. For this standard, Nb
	 * = 4
	 */
	private static final int Nb = 4;
	/**
	 * Number of 32-bit words comprising the Cipher Key. For this standard, Nk = 4
	 */
	private static final int Nk = 4;
	/**
	 * Number of rounds, which is a function of Nk and Nb (which is fixed). For this
	 * standard, Nr = 10
	 */
	private static final int Nr = 10;

	/**
	 * The S-box used in the <code>SubBytes()</code> transformation
	 */
	public static final int[][] SBOX = {
			{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
			{ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
			{ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
			{ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
			{ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
			{ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
			{ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
			{ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
			{ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
			{ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
			{ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
			{ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
			{ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
			{ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
			{ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
			{ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 } };

	/**
	 * The inverse S-box used in the <code>InvSubBytes()</code> transformation
	 */
	public static final int[][] INVERSE_SBOX = {
			{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
			{ 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
			{ 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
			{ 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
			{ 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
			{ 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
			{ 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
			{ 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
			{ 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
			{ 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
			{ 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
			{ 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
			{ 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
			{ 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
			{ 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
			{ 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d } };

	//@formatter:off
	
	/**
	 * The fixed polynomial matrix used in the <code>MixColumns()</code> transformation
	 */
	public static final int[][] FPM = { 
			{ 0x02, 0x03, 0x01, 0x01 }, 
			{ 0x01, 0x02, 0x03, 0x01 },
			{ 0x01, 0x01, 0x02, 0x03 }, 
			{ 0x03, 0x01, 0x01, 0x02 } };

	/**
	 * The inverse fixed polynomial matrix used in the <code>InvMixColumns()</code> transformation
	 */
	public static final int[][] INVERSE_FPM = { 
			{ 0x0e, 0x0b, 0x0d, 0x09 },
			{ 0x09, 0x0e, 0x0b, 0x0d },
			{ 0x0d, 0x09, 0x0e, 0x0b }, 
			{ 0x0b, 0x0d, 0x09, 0x0e } };
	
	/**
	 * The round constant word array
	 */
	public static final int[][] RCON = { 
			{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36},
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };
	
	//@formatter:on

	/**
	 * Field variable that is used for debugging and testing. If true debugger lines
	 * are printed out, otherwise if false
	 */
	public static boolean debug = false;

	/**
	 * Key that will be used
	 */
	public int[][] key = null;
	/**
	 * Key schedule that will be used
	 */
	public int[][] keySchedule = null;
	/**
	 * Mode of operation that will be used
	 */
	public ModeOfOperation modeOfOperation = null;
	/**
	 * IV in string hex format that will be used
	 */
	public String ivString = "00000000000000000000000000000000";

	/**
	 * @return true if in debug mode, false otherwise
	 */
	public static boolean isDebug() {
		return debug;
	}

	/**
	 * Sets the debug mode
	 * 
	 * @param debug
	 */
	public static void setDebug(boolean debug) {
		AES128.debug = debug;
	}

	/**
	 * @return key length
	 */
	public int getKeyLength() {
		return KEY_LENGTH;
	}

	/**
	 * @return data block length
	 */
	public int getDataBlockLength() {
		return DATA_BLOCK_LENGTH;
	}

	/**
	 * @return Nb
	 */
	public static int getNb() {
		return Nb;
	}

	/**
	 * @return Nk
	 */
	public static int getNk() {
		return Nk;
	}

	/**
	 * @return Nr
	 */
	public static int getNr() {
		return Nr;
	}

	/**
	 * @return s-box
	 */
	public static int[][] getSbox() {
		return SBOX;
	}

	/**
	 * @return inverse s-box
	 */
	public static int[][] getInverseSbox() {
		return INVERSE_SBOX;
	}

	/**
	 * @return FPM
	 */
	public static int[][] getFPM() {
		return FPM;
	}

	/**
	 * @return inverse FPM
	 */
	public static int[][] getInverseFPM() {
		return INVERSE_FPM;
	}

	/**
	 * @return RCON
	 */
	public static int[][] getRCON() {
		return RCON;
	}

	/**
	 * @return key
	 */
	public int[][] getKey() {
		return key;
	}

	/**
	 * @param key that was initialized
	 */
	public void setKey(int[][] key) {
		if (key.length != Nk || key[0].length != Nb) {
			throw new IllegalArgumentException("The key size does not meet the specification criteria!");
		}

		this.key = key;
		this.keySchedule = keyExpansion(key);
	}

	/**
	 * @return key schedule for the key, if it was initialized, null otherwise
	 */
	public int[][] getKeySchedule() {
		return keySchedule;
	}

	/**
	 * @return current mode of operation, if it was initialized, null otherwise
	 */
	public ModeOfOperation getModeOfOperation() {
		return modeOfOperation;
	}

	/**
	 * @param modeOfOperation that was initialized
	 */
	public void setModeOfOperation(ModeOfOperation modeOfOperation) {
		this.modeOfOperation = modeOfOperation;
	}

	/**
	 * @return IV string that was initialized, all zeros otherwise
	 */
	public String getIvString() {
		return ivString;
	}

	/**
	 * @param ivString IV string value in hex format
	 */
	public void setIvString(String ivString) {
		this.ivString = ivString;
	}

	/**
	 * Method that enables abstract use of encryption
	 */
	@Override
	public int[][] encrypt(int[][] plaintext) {
		if (Objects.isNull(key)) {
			throw new IllegalArgumentException("The key has not been initialized!");
		}

		int colNum = plaintext[0].length;

		if (plaintext.length != Nb || colNum % Nk != 0) {
			throw new IllegalArgumentException("The argument is not valid!");
		}

		if (colNum == Nk) {
			return cipher(plaintext, this.keySchedule);
		}

		int[][] result = new int[Nb][colNum];

		switch (modeOfOperation) {
		case ECB -> {
			for (int k = 0; k < colNum / 4; k++) {
				int[][] inNumK = MatrixUtils.getMatrixColumns(plaintext, k * Nk, k * Nk + 4);
				int[][] cipherNumK = cipher(inNumK, this.keySchedule);
				result = MatrixUtils.insertMatrixColumns(result, cipherNumK, k * 4);
			}
		}
		case CTR -> {
			for (int k = 0; k < colNum / 4; k++) {
				int[][] iv = AlgorithmUtils.createIV(ivString, k);
				int[][] cipherNumK = cipher(iv, this.keySchedule);
				int[][] inNumK = MatrixUtils.getMatrixColumns(plaintext, k * Nk, k * Nk + 4);
				result = MatrixUtils.insertMatrixColumns(result, FiniteFieldsUtil.add(cipherNumK, inNumK), k * 4);
			}
		}
		default ->
			throw new IllegalArgumentException(String.format("Unsupported mode of operation: '%s'!", modeOfOperation));
		}

		return result;
	}

	/**
	 * Method that enables abstract use of decryption
	 */
	@Override
	public int[][] decrypt(int[][] ciphertext) {
		if (Objects.isNull(key)) {
			throw new IllegalArgumentException("The key has not been initialized!");
		}

		int colNum = ciphertext[0].length;

		if (ciphertext.length != Nb || colNum % Nk != 0) {
			throw new IllegalArgumentException("The argument is not valid!");
		}

		if (colNum == Nk) {
			return invCipher(ciphertext, this.keySchedule);
		}

		int[][] result = new int[Nb][colNum];

		switch (modeOfOperation) {
		case ECB -> {
			for (int k = 0; k < colNum / 4; k++) {
				int[][] inNumK = MatrixUtils.getMatrixColumns(ciphertext, k * Nk, k * Nk + 4);
				int[][] invCipherNumK = invCipher(inNumK, this.keySchedule);
				result = MatrixUtils.insertMatrixColumns(result, invCipherNumK, k * 4);
			}
		}
		case CTR -> {
			for (int k = 0; k < colNum / 4; k++) {
				int[][] iv = AlgorithmUtils.createIV(ivString, k);
				int[][] cipherNumK = cipher(iv, this.keySchedule);
				int[][] inNumK = MatrixUtils.getMatrixColumns(ciphertext, k * Nk, k * Nk + 4);
				result = MatrixUtils.insertMatrixColumns(result, FiniteFieldsUtil.add(cipherNumK, inNumK), k * 4);
			}
		}
		default ->
			throw new IllegalArgumentException(String.format("Unsupported mode of operation: '%s'!", modeOfOperation));
		}

		return result;
	}

	@Override
	public int[][] cipher(int[][] in, int[][] word) {
		if (debug) {
			System.out.println(String.format("PLAINTEXT: %s", IOUtils.parseState(in)));
			System.out.println(String.format("KEY: %s", IOUtils.parseState(AlgorithmUtils.getRoundKey(word, 0))));
			System.out.println(String.format("CIPHER (ENCRYPT):"));
			System.out.println(String.format("round[%2d].%s %s", 0, "input", IOUtils.parseState(in)));
			System.out.println(String.format("round[%2d].%s %s", 0, "k_sch",
					IOUtils.parseState(AlgorithmUtils.getRoundKey(word, 0))));
		}

		int[][] state = AlgorithmUtils.addRoundKey(in, word, 0);

		for (int round = 1; round < Nr; round++) {
			if (debug) {
				System.out.println(String.format("round[%2d].%s %s", round, "start", IOUtils.parseState(state)));
			}

			state = subBytes(state);

			if (debug) {
				System.out.println(String.format("round[%2d].%s %s", round, "s_box", IOUtils.parseState(state)));
			}

			state = shiftRows(state);

			if (debug) {
				System.out.println(String.format("round[%2d].%s %s", round, "s_row", IOUtils.parseState(state)));
			}

			state = mixColumns(state);

			if (debug) {
				System.out.println(String.format("round[%2d].%s %s", round, "m_col", IOUtils.parseState(state)));
			}

			state = addRoundKey(state, AlgorithmUtils.getRoundKey(word, round));

			if (debug) {
				System.out.println(String.format("round[%2d].%s %s", round, "k_sch",
						IOUtils.parseState(AlgorithmUtils.getRoundKey(word, round))));
			}
		}

		if (debug) {
			System.out.println(String.format("round[%2d].%s %s", Nr, "start", IOUtils.parseState(state)));
		}

		state = subBytes(state);

		if (debug) {
			System.out.println(String.format("round[%2d].%s %s", Nr, "s_box", IOUtils.parseState(state)));
		}

		state = shiftRows(state);

		if (debug) {
			System.out.println(String.format("round[%2d].%s %s", Nr, "s_row", IOUtils.parseState(state)));
			System.out.println(String.format("round[%2d].%s %s", Nr, "k_sch",
					IOUtils.parseState(AlgorithmUtils.getRoundKey(word, Nr))));
		}

		state = addRoundKey(state, AlgorithmUtils.getRoundKey(word, Nr));

		if (debug) {
			System.out.println(String.format("round[%2d].%s %s", Nr, "output", IOUtils.parseState(state)));
		}

		return state;
	}

	@Override
	public int[][] invCipher(int[][] in, int[][] word) {
		if (debug) {
			System.out.println(String.format("INVERSE CIPHER (DECRYPT):"));
			System.out.println(String.format("round[%2d].%s %s", 0, "iinput", IOUtils.parseState(in)));
			System.out.println(String.format("round[%2d].%s %s", 0, "ik_sch",
					IOUtils.parseState(AlgorithmUtils.getRoundKey(word, Nr))));
		}

		int[][] state = AlgorithmUtils.addRoundKey(in, AlgorithmUtils.getRoundKey(word, Nr));

		for (int round = Nr - 1, i = 1; round > 0; round--, i++) {
			if (debug) {
				System.out.println(String.format("round[%2d].%s %s", i, "istart", IOUtils.parseState(state)));
			}

			state = invShiftRows(state);

			if (debug) {
				System.out.println(String.format("round[%2d].%s %s", i, "is_row", IOUtils.parseState(state)));
			}

			state = invSubBytes(state);

			if (debug) {
				System.out.println(String.format("round[%2d].%s %s", i, "is_box", IOUtils.parseState(state)));
			}

			state = addRoundKey(state, AlgorithmUtils.getRoundKey(word, round));

			if (debug) {
				System.out.println(String.format("round[%2d].%s %s", i, "ik_sch",
						IOUtils.parseState(AlgorithmUtils.getRoundKey(word, round))));
				System.out.println(String.format("round[%2d].%s %s", i, "ik_add", IOUtils.parseState(state)));
			}

			state = invMixColumns(state);

		}

		if (debug) {
			System.out.println(String.format("round[%2d].%s %s", Nr, "istart", IOUtils.parseState(state)));
		}

		state = invShiftRows(state);

		if (debug) {
			System.out.println(String.format("round[%2d].%s %s", Nr, "is_row", IOUtils.parseState(state)));
		}

		state = invSubBytes(state);

		if (debug) {
			System.out.println(String.format("round[%2d].%s %s", Nr, "is_box", IOUtils.parseState(state)));
		}

		state = addRoundKey(state, AlgorithmUtils.getRoundKey(word, 0));

		if (debug) {
			System.out.println(String.format("round[%2d].%s %s", Nr, "ik_sch",
					IOUtils.parseState(AlgorithmUtils.getRoundKey(word, 0))));
			System.out.println(String.format("round[%2d].%s %s", Nr, "ioutput", IOUtils.parseState(state)));
		}

		return state;
	}

	@Override
	public int[][] keyExpansion(int[][] key) {
		int result[][] = new int[Nk][Nb * (Nr + 1)];

		for (int i = 0; i < Nk; i++) {
			AlgorithmUtils.insertColumn(result, i, key[i]);
		}

		for (int i = Nk; i < Nb * (Nr + 1); i++) {
			int[] tmp = AlgorithmUtils.getColumn(result, i - 1);

			if (i % Nk == 0) {
				tmp = AlgorithmUtils.xorWords(subWord(rotWord(tmp)), AlgorithmUtils.getColumn(RCON, (i - 1) / Nk));
			}

			// Part of code used for AES-192 & AES-256.

//			else if ((Nk > 6) && (i % Nk == 4)) {
//				tmp = subWord(tmp);
//			}

			AlgorithmUtils.insertColumn(result, i,
					AlgorithmUtils.xorWords(AlgorithmUtils.getColumn(result, i - Nk), tmp));
		}

		return result;
	}

	@Override
	public int[][] addRoundKey(int[][] state, int[][] roundKey) {
		return AlgorithmUtils.addRoundKey(state, roundKey);
	}

	@Override
	public int[][] subBytes(int[][] state) {
		int rows = state.length;
		int cols = state[0].length;
		int result[][] = new int[rows][cols];

		for (int i = 0; i < rows; i++) {
			for (int j = 0; j < cols; j++) {
				String element = Integer.toHexString(state[i][j]);
				int first = (Integer.parseInt(element, 16) >> 4) & 0x0f;
				int second = Integer.parseInt(element, 16) & 0x0f;
				result[i][j] = SBOX[first][second];
			}
		}

		return result;
	}

	@Override
	public int[][] invSubBytes(int[][] state) {
		int rows = state.length;
		int cols = state[0].length;
		int result[][] = new int[rows][cols];

		for (int i = 0; i < rows; i++) {
			for (int j = 0; j < cols; j++) {
				String element = Integer.toHexString(state[i][j]);
				int first = (Integer.parseInt(element, 16) >> 4) & 0x0f;
				int second = Integer.parseInt(element, 16) & 0x0f;
				result[i][j] = INVERSE_SBOX[first][second];
			}
		}

		return result;
	}

	@Override
	public int[][] shiftRows(int[][] state) {
		return AlgorithmUtils.shiftRows(state, "LEFT");
	}

	@Override
	public int[][] invShiftRows(int[][] state) {
		return AlgorithmUtils.shiftRows(state, "RIGHT");
	}

	@Override
	public int[][] mixColumns(int[][] state) {
		return AlgorithmUtils.mixColumns(state, FPM);
	}

	@Override
	public int[][] invMixColumns(int[][] state) {
		return AlgorithmUtils.mixColumns(state, INVERSE_FPM);
	}

	@Override
	public int[] rotWord(int[] word) {
		int result[] = new int[word.length];

		for (int i = 0, length = result.length; i < length; i++) {
			result[i] = word[(i + 1) % length];
		}

		return result;
	}

	@Override
	public int[] subWord(int[] word) {
		int rows = word.length;
		int result[] = new int[rows];

		for (int i = 0; i < rows; i++) {
			String element = Integer.toHexString(word[i]);
			int first = (Integer.parseInt(element, 16) >> 4) & 0x0f;
			int second = Integer.parseInt(element, 16) & 0x0f;
			result[i] = SBOX[first][second];
		}

		return result;
	}

	@Override
	public String toString() {
		return "AES128";
	}

}
